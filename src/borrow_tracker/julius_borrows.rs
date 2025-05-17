use std::cell::RefCell;
use std::rc::Rc;

use rustc_abi::Size;
use rustc_ast::Mutability;
use rustc_const_eval::interpret::{
    AllocId, AllocKind, AllocRange, InterpResult, alloc_range, interp_ok,
};
use rustc_data_structures::fx::FxHashSet;
use rustc_middle::mir::RetagKind;
use rustc_middle::mir::interpret::CheckInAllocMsg;
use rustc_middle::ty::{self, Ty};
use tracing::trace;

use self::stacked::BasicStackCheckerBuilder;
use super::stacked_borrows::diagnostics::RetagCause;
use super::{BorTag, GlobalState, GlobalStateInner, JuliusBorrowsFields, ProtectorKind};
use crate::concurrency::data_race::{NaReadType, NaWriteType};
use crate::diagnostics::EvalContextExt as _;
use crate::helpers::EvalContextExt as _;
use crate::rustc_middle::ty::layout::HasTypingEnv;
use crate::{
    AccessKind, ImmTy, Item, MPlaceTy, MemoryKind, MiriMachine, NonHaltingDiagnostic, Permission,
    PlaceTy, Pointer, Provenance, ProvenanceExtra, VisitProvenance,
};

mod stacked;

pub trait CheckerBuilder {
    type Checker: Checker;
    fn build_checker(
        &self,
        id: AllocId,
        size: Size,
        kind: MemoryKind,
        root: BorTag,
    ) -> Self::Checker;
}

#[allow(unused_variables)]
pub trait Checker: std::fmt::Debug {
    fn check_access<'ecx, 'tcx>(
        &mut self,
        mode: AccessKind,
        alloc_id: AllocId,
        tag: BorTag,
        range: AllocRange,
        machine: &'ecx MiriMachine<'tcx>,
    ) -> InterpResult<'tcx>
    where
        'tcx: 'ecx,
    {
        interp_ok(())
    }

    fn check_access_wildcard<'ecx, 'tcx>(
        &mut self,
        mode: AccessKind,
        alloc_id: AllocId,
        range: AllocRange,
        machine: &'ecx MiriMachine<'tcx>,
    ) -> InterpResult<'tcx>
    where
        'tcx: 'ecx,
    {
        // ignore wildcards for now
        interp_ok(())
    }

    fn check_dealloc<'ecx, 'tcx>(
        &mut self,
        alloc_id: AllocId,
        tag: BorTag,
        size: Size,
        machine: &'ecx MiriMachine<'tcx>,
    ) -> InterpResult<'tcx>
    where
        'tcx: 'ecx,
    {
        interp_ok(())
    }

    fn check_dealloc_wildcard<'ecx, 'tcx>(
        &mut self,
        alloc_id: AllocId,
        size: Size,
        machine: &'ecx MiriMachine<'tcx>,
    ) -> InterpResult<'tcx>
    where
        'tcx: 'ecx,
    {
        // ignore wildcards for now
        interp_ok(())
    }

    fn remove_unreachable_tags(&mut self, live_tags: &FxHashSet<BorTag>) {
        // Default implementation does nothing.
    }

    fn release_protector<'ecx, 'tcx>(
        &mut self,
        machine: &'ecx MiriMachine<'tcx>,
        global: &GlobalState,
        tag: BorTag,
        alloc_id: AllocId,
    ) -> InterpResult<'tcx>
    where
        'tcx: 'ecx,
    {
        interp_ok(())
    }

    fn retag_pointer_value<'tcx>(
        &mut self,
        kind: RetagKind,
        val: &ImmTy<'tcx>,
    ) -> InterpResult<'tcx, ImmTy<'tcx>> {
        interp_ok(val.clone())
    }

    fn expose_tag<'tcx>(&mut self, tag: BorTag) {
        // implemented by stacked borrows, not by tree borrows
    }

    fn protect_place<'tcx>(
        &mut self,
        place: &MPlaceTy<'tcx>,
    ) -> InterpResult<'tcx, MPlaceTy<'tcx>> {
        interp_ok(place.clone())
    }

    fn give_pointer_debug_name<'tcx>(
        &mut self,
        ptr: Pointer,
        nth_parent: u8,
        name: &str,
    ) -> InterpResult<'tcx> {
        interp_ok(())
    }

    fn print_borrow_state<'tcx>(
        &mut self,
        alloc_id: AllocId,
        show_unnamed: bool,
    ) -> InterpResult<'tcx> {
        interp_ok(())
    }
}

#[derive(Debug, Clone)]
pub struct Custom {
    checker: Rc<RefCell<dyn Checker>>,
    fields: JuliusBorrowsFields,
}

impl<'tcx> Custom {
    pub fn new_allocation(
        id: AllocId,
        size: Size,
        state: &mut GlobalStateInner,
        kind: MemoryKind,
        machine: &MiriMachine<'tcx>,
        fields: JuliusBorrowsFields,
    ) -> Self {
        let root = state.root_ptr_tag(id, machine);

        let b = BasicStackCheckerBuilder.build_checker(id, size, kind, root);
        let checker = Rc::new(RefCell::new(b));
        Self { checker, fields }
    }

    pub fn before_memory_access(
        &mut self,
        access_kind: AccessKind,
        alloc_id: AllocId,
        prov: ProvenanceExtra,
        range: AllocRange,
        machine: &MiriMachine<'tcx>,
    ) -> InterpResult<'tcx> {
        match prov {
            ProvenanceExtra::Concrete(bor_tag) => {
                let mut checker = self.checker.borrow_mut();
                checker.check_access(access_kind, alloc_id, bor_tag, range, machine)
            }
            ProvenanceExtra::Wildcard => {
                let mut checker = self.checker.borrow_mut();
                checker.check_access_wildcard(access_kind, alloc_id, range, machine)
            }
        }
    }

    pub fn before_memory_deallocation(
        &mut self,
        alloc_id: AllocId,
        prov: ProvenanceExtra,
        size: Size,
        machine: &MiriMachine<'tcx>,
    ) -> InterpResult<'tcx> {
        match prov {
            ProvenanceExtra::Concrete(bor_tag) => {
                let mut checker = self.checker.borrow_mut();
                checker.check_dealloc(alloc_id, bor_tag, size, machine)
            }
            ProvenanceExtra::Wildcard => {
                let mut checker = self.checker.borrow_mut();
                checker.check_dealloc_wildcard(alloc_id, size, machine)
            }
        }
    }

    pub fn remove_unreachable_tags(&mut self, live_tags: &FxHashSet<BorTag>) {
        let mut checker = self.checker.borrow_mut();
        checker.remove_unreachable_tags(live_tags);
    }

    pub fn release_protector(
        &mut self,
        machine: &MiriMachine<'tcx>,
        global: &GlobalState,
        tag: BorTag,
        alloc_id: AllocId, // diagnostics
    ) -> InterpResult<'tcx> {
        let mut checker = self.checker.borrow_mut();
        checker.release_protector(machine, global, tag, alloc_id)
    }

    fn expose_tag(&mut self, tag: BorTag) {
        let mut checker = self.checker.borrow_mut();
        checker.expose_tag(tag)
    }

    fn protect_place(&mut self, place: &MPlaceTy<'tcx>) -> InterpResult<'tcx, MPlaceTy<'tcx>> {
        let mut checker = self.checker.borrow_mut();
        checker.protect_place(place)
    }

    fn give_pointer_debug_name(
        &mut self,
        ptr: Pointer,
        nth_parent: u8,
        name: &str,
    ) -> InterpResult<'tcx> {
        let mut checker = self.checker.borrow_mut();
        checker.give_pointer_debug_name(ptr, nth_parent, name)
    }

    fn print_borrow_state(&self, alloc_id: AllocId, show_unnamed: bool) -> InterpResult<'tcx> {
        let mut checker = self.checker.borrow_mut();
        checker.print_borrow_state(alloc_id, show_unnamed)
    }

    fn for_each(&mut self, range: AllocRange, f: impl Fn()-> InterpResult<'tcx>) -> InterpResult<'tcx> {
        f()
    }
}

impl VisitProvenance for Custom {
    fn visit_provenance(&self, _visit: &mut crate::VisitWith<'_>) {
        // todo
    }
}

enum NewPermission {
    Uniform {
        perm: Permission,
        access: Option<AccessKind>,
        protector: Option<ProtectorKind>,
    },
    FreezeSensitive {
        freeze_perm: Permission,
        freeze_access: Option<AccessKind>,
        freeze_protector: Option<ProtectorKind>,
        nonfreeze_perm: Permission,
        nonfreeze_access: Option<AccessKind>,
    },
}

impl NewPermission {
    fn protector(&self) -> Option<ProtectorKind> {
        match self {
            NewPermission::Uniform { protector, .. } => *protector,
            NewPermission::FreezeSensitive { freeze_protector, .. } => *freeze_protector,
        }
    }

    /// A key function: determine the permissions to grant at a retag for the given kind of
    /// reference/pointer.
    fn from_ref_ty<'tcx>(ty: Ty<'tcx>, kind: RetagKind, cx: &crate::MiriInterpCx<'tcx>) -> Self {
        let protector = (kind == RetagKind::FnEntry).then_some(ProtectorKind::StrongProtector);
        match ty.kind() {
            ty::Ref(_, pointee, Mutability::Mut) => {
                if kind == RetagKind::TwoPhase {
                    // We mostly just give up on 2phase-borrows, and treat these exactly like raw pointers.
                    assert!(protector.is_none()); // RetagKind can't be both FnEntry and TwoPhase.
                    NewPermission::Uniform {
                        perm: Permission::SharedReadWrite,
                        access: None,
                        protector: None,
                    }
                } else if pointee.is_unpin(*cx.tcx, cx.typing_env()) {
                    // A regular full mutable reference. On `FnEntry` this is `noalias` and `dereferenceable`.
                    NewPermission::Uniform {
                        perm: Permission::Unique,
                        access: Some(AccessKind::Write),
                        protector,
                    }
                } else {
                    // `!Unpin` dereferences do not get `noalias` nor `dereferenceable`.
                    NewPermission::Uniform {
                        perm: Permission::SharedReadWrite,
                        access: None,
                        protector: None,
                    }
                }
            }
            ty::RawPtr(_, Mutability::Mut) => {
                assert!(protector.is_none()); // RetagKind can't be both FnEntry and Raw.
                // Mutable raw pointer. No access, not protected.
                NewPermission::Uniform {
                    perm: Permission::SharedReadWrite,
                    access: None,
                    protector: None,
                }
            }
            ty::Ref(_, _pointee, Mutability::Not) => {
                // Shared references. If frozen, these get `noalias` and `dereferenceable`; otherwise neither.
                NewPermission::FreezeSensitive {
                    freeze_perm: Permission::SharedReadOnly,
                    freeze_access: Some(AccessKind::Read),
                    freeze_protector: protector,
                    nonfreeze_perm: Permission::SharedReadWrite,
                    // Inside UnsafeCell, this does *not* count as an access, as there
                    // might actually be mutable references further up the stack that
                    // we have to keep alive.
                    nonfreeze_access: None,
                    // We do not protect inside UnsafeCell.
                    // This fixes https://github.com/rust-lang/rust/issues/55005.
                }
            }
            ty::RawPtr(_, Mutability::Not) => {
                assert!(protector.is_none()); // RetagKind can't be both FnEntry and Raw.
                // `*const T`, when freshly created, are read-only in the frozen part.
                NewPermission::FreezeSensitive {
                    freeze_perm: Permission::SharedReadOnly,
                    freeze_access: Some(AccessKind::Read),
                    freeze_protector: None,
                    nonfreeze_perm: Permission::SharedReadWrite,
                    nonfreeze_access: None,
                }
            }
            _ => unreachable!(),
        }
    }
}

impl<'tcx> EvalContextExt<'tcx> for crate::MiriInterpCx<'tcx> {}
pub trait EvalContextExt<'tcx>: crate::MiriInterpCxExt<'tcx> {
    fn jb_retag_ptr_value(
        &mut self,
        kind: RetagKind,
        val: &ImmTy<'tcx>,
        fields: JuliusBorrowsFields,
    ) -> InterpResult<'tcx, ImmTy<'tcx>> {
        let this = self.eval_context_mut();
        let new_perm = NewPermission::from_ref_ty(val.layout.ty, kind, this);
        this.sb_retag_reference(val, new_perm, fields)
    }

    fn jb_retag_place_contents(
        &mut self,
        kind: RetagKind,
        place: &PlaceTy<'tcx>,
        fields: JuliusBorrowsFields,
    ) -> InterpResult<'tcx> {
        interp_ok(())
    }

    fn jb_protect_place(
        &mut self,
        place: &MPlaceTy<'tcx>,
        fields: JuliusBorrowsFields,
    ) -> InterpResult<'tcx, MPlaceTy<'tcx>> {
        let this = self.eval_context_mut();

        let new_perm = NewPermission::Uniform {
            perm: Permission::Unique,
            access: Some(AccessKind::Write),
            protector: Some(ProtectorKind::StrongProtector),
        };

        this.jb_retag_place(place, new_perm, (), fields)
    }

    fn jb_expose_tag(
        &self,
        alloc_id: AllocId,
        tag: BorTag,
        fields: JuliusBorrowsFields,
    ) -> InterpResult<'tcx> {
        let this = self.eval_context_ref();

        // Function pointers and dead objects don't have an alloc_extra so we ignore them.
        // This is okay because accessing them is UB anyway, no need for any Tree Borrows checks.
        // NOT using `get_alloc_extra_mut` since this might be a read-only allocation!
        let kind = this.get_alloc_info(alloc_id).kind;
        match kind {
            AllocKind::LiveData => {
                // This should have alloc_extra data, but `get_alloc_extra` can still fail
                // if converting this alloc_id from a global to a local one
                // uncovers a non-supported `extern static`.
                let alloc_extra = this.get_alloc_extra(alloc_id)?;
                trace!("Custom Borrows tag {tag:?} exposed in {alloc_id:?}");
                alloc_extra.borrow_tracker_jb().borrow_mut().expose_tag(tag);
            }
            AllocKind::Function | AllocKind::VTable | AllocKind::Dead => {
                // No need to do anything, we don't track these.
                trace!("Custom Borrows tag {tag:?} not exposed in {alloc_id:?} (no tracking)");
            }
        }
        interp_ok(())
    }

    fn jb_give_pointer_debug_name(
        &mut self,
        ptr: Pointer,
        nth_parent: u8,
        name: &str,
    ) -> InterpResult<'tcx> {
        // return interp_ok(());
        let this = self.eval_context_ref();
        let (id, _, _) = this.ptr_get_alloc_id(ptr, 0)?;
        let extra = this.get_alloc_extra(id)?;
        let cell = extra.borrow_tracker_jb();
        let mut borrow_tracker = cell.borrow_mut();
        borrow_tracker.give_pointer_debug_name(ptr, nth_parent, name)
    }

    fn jb_print_borrow_state(
        &mut self,
        alloc_id: AllocId,
        show_unnamed: bool,
    ) -> InterpResult<'tcx> {
        // return interp_ok(());
        let this = self.eval_context_ref();
        let extra = this.get_alloc_extra(alloc_id)?;
        let cell = extra.borrow_tracker_jb();
        let borrow_tracker = cell.borrow();
        borrow_tracker.print_borrow_state(alloc_id, show_unnamed)
    }
}

impl<'tcx, 'ecx> EvalContextPrivExt<'tcx, 'ecx> for crate::MiriInterpCx<'tcx> {}
trait EvalContextPrivExt<'tcx, 'ecx>: crate::MiriInterpCxExt<'tcx> {
    fn jb_retag_place(
        &mut self,
        place: &MPlaceTy<'tcx>,
        new_perm: NewPermission,
        info: (),
        fields: JuliusBorrowsFields,
    ) -> InterpResult<'tcx, MPlaceTy<'tcx>> {
        let this = self.eval_context_mut();
        let size = this.size_and_align_of_mplace(place)?.map(|(size, _)| size);

        let size = match size {
            Some(size) => size,
            None => {
                if !this.machine.sb_extern_type_warned.replace(true) {
                    this.emit_diagnostic(NonHaltingDiagnostic::ExternTypeReborrow);
                }
                return interp_ok(place.clone());
            }
        };

        let new_tag = this.machine.borrow_tracker.as_mut().unwrap().get_mut().new_ptr();

        let new_prov = this.jb_reborrow(
            place, size, new_perm, new_tag,
            // retag_info, // diagnostics info about this retag
        )?;

        interp_ok(place.clone().map_provenance(|_| new_prov.unwrap()))
    }

    fn jb_reborrow(
        &mut self,
        place: &MPlaceTy<'tcx>,
        size: Size,
        new_perm: NewPermission,
        new_tag: BorTag,
        // retag_info: RetagInfo, // diagnostics info about this retag
    ) -> InterpResult<'tcx, Option<Provenance>> {
        let this = self.eval_context_mut();
        // Ensure we bail out if the pointer goes out-of-bounds (see miri#1050).
        this.check_ptr_access(place.ptr(), size, CheckInAllocMsg::Dereferenceable)?;
        if size == Size::ZERO {
            trace!(
                "reborrow of size 0: reference {:?} derived from {:?} (pointee {})",
                new_tag,
                place.ptr(),
                place.layout.ty,
            );
            // Don't update any stacks for a zero-sized access; borrow stacks are per-byte and this
            // touches no bytes so there is no stack to put this tag in.
            // However, if the pointer for this operation points at a real allocation we still
            // record where it was created so that we can issue a helpful diagnostic if there is an
            // attempt to use it for a non-zero-sized access.
            // Dangling slices are a common case here; it's valid to get their length but with raw
            // pointer tagging for example all calls to get_unchecked on them are invalid.
            if let Ok((alloc_id, _, _)) = this.ptr_try_get_alloc_id(place.ptr(), 0) {
                // log_creation(this, Some((alloc_id, base_offset, orig_tag)))?;
                // Still give it the new provenance, it got retagged after all.
                return interp_ok(Some(Provenance::Concrete { alloc_id, tag: new_tag }));
            } else {
                // This pointer doesn't come with an AllocId. :shrug:
                // log_creation(this, None)?;
                // Provenance unchanged.
                return interp_ok(place.ptr().provenance);
            }
        }

        let (alloc_id, base_offset, orig_tag) = this.ptr_get_alloc_id(place.ptr(), 0)?;

        if let Some(protect) = new_perm.protector() {
            // See comment in `Stack::item_invalidated` for why we store the tag twice.
            this.frame_mut()
                .extra
                .borrow_tracker
                .as_mut()
                .unwrap()
                .protected_tags
                .push((alloc_id, new_tag));
            this.machine
                .borrow_tracker
                .as_mut()
                .unwrap()
                .get_mut()
                .protected_tags
                .insert(new_tag, protect);
        }

        match new_perm {
            NewPermission::Uniform { perm, access, protector } => {
                assert!(perm != Permission::SharedReadOnly);
                let (alloc_extra, machine) = this.get_alloc_extra_mut(alloc_id)?;

                let jb = alloc_extra.borrow_tracker_jb_mut().get_mut();
                let item = Item::new(new_tag, perm, protector.is_some());
                let range = alloc_range(base_offset, size);
                let global = machine.borrow_tracker.as_ref().unwrap().borrow();

                jb.for_each(range, || interp_ok(()))?;
                drop(global);

                if let Some(access) = access {
                    assert_eq!(access, AccessKind::Write);
                    // Make sure the data race model also knows about this.
                    if let Some(data_race) = alloc_extra.data_race.as_vclocks_mut() {
                        data_race.write(
                            alloc_id,
                            range,
                            NaWriteType::Retag,
                            Some(place.layout.ty),
                            machine,
                        )?;
                    }
                }
            }
            NewPermission::FreezeSensitive {
                freeze_perm,
                freeze_access,
                freeze_protector,
                nonfreeze_perm,
                nonfreeze_access,
            } => {
                let alloc_extra = this.get_alloc_extra(alloc_id)?;
                let mut borrows = alloc_extra.borrow_tracker_jb().borrow_mut();
                this.visit_freeze_sensitive(place, size, |mut range, frozen| {
                    range.start += base_offset;

                    let (perm, access, protector) = if frozen {
                        (freeze_perm, freeze_access, freeze_protector)
                    } else {
                        (nonfreeze_perm, nonfreeze_access, None)
                    };

                    let item = Item::new(new_tag, perm, protector.is_some());
                    let global = this.machine.borrow_tracker.as_ref().unwrap().borrow();

                    borrows.for_each(range, || interp_ok(()))?;
                    drop(global);
                    if let Some(access) = access {
                        assert_eq!(access, AccessKind::Read);
                        // Make sure the data race model also knows about this.
                        if let Some(data_race) = alloc_extra.data_race.as_vclocks_ref() {
                            data_race.read(
                                alloc_id,
                                range,
                                NaReadType::Retag,
                                Some(place.layout.ty),
                                &this.machine,
                            )?;
                        }
                    }

                    interp_ok(())
                })?;
            }
        }

        interp_ok(Some(Provenance::Concrete { alloc_id, tag: new_tag }))
    }

    fn sb_retag_reference(
        &mut self,
        val: &ImmTy<'tcx>,
        new_perm: NewPermission,
        fields: JuliusBorrowsFields,
    ) -> InterpResult<'tcx, ImmTy<'tcx>> {
        let this = self.eval_context_mut();
        let place = this.ref_to_mplace(val)?;
        let new_place = this.jb_retag_place(&place, new_perm, (), fields)?;
        interp_ok(ImmTy::from_immediate(new_place.to_ref(this), val.layout))
    }
}
