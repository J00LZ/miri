use std::cell::RefCell;
use std::rc::Rc;

use rustc_abi::Size;
use rustc_const_eval::interpret::{interp_ok, AllocId, AllocKind, AllocRange, InterpResult};
use rustc_data_structures::fx::FxHashSet;
use rustc_middle::mir::RetagKind;
use tracing::trace;
use self::stacked::BasicStackCheckerBuilder;

use super::{BorTag, GlobalState, GlobalStateInner};
use crate::{
    AccessKind, ImmTy, MPlaceTy, MemoryKind, MiriMachine, PlaceTy, Pointer, ProvenanceExtra,
    VisitProvenance,
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

    fn expose_tag<'tcx>(&mut self, tag: BorTag) -> InterpResult<'tcx> {
        interp_ok(())
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
}

impl<'tcx> Custom {
    pub fn new_allocation(
        id: AllocId,
        size: Size,
        state: &mut GlobalStateInner,
        kind: MemoryKind,
        machine: &MiriMachine<'tcx>,
    ) -> Self {
        let root = state.root_ptr_tag(id, machine);

        let b = BasicStackCheckerBuilder.build_checker(id, size, kind, root);
        let checker = Rc::new(RefCell::new(b));
        Self { checker }
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

    fn expose_tag(&mut self, tag: BorTag) -> InterpResult<'tcx> {
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
}

impl VisitProvenance for Custom {
    fn visit_provenance(&self, _visit: &mut crate::VisitWith<'_>) {
        // todo
    }
}

impl<'tcx> EvalContextExt<'tcx> for crate::MiriInterpCx<'tcx> {}
pub trait EvalContextExt<'tcx>: crate::MiriInterpCxExt<'tcx> {
    fn jb_retag_ptr_value(
        &mut self,
        kind: RetagKind,
        val: &ImmTy<'tcx>,
    ) -> InterpResult<'tcx, ImmTy<'tcx>> {
        interp_ok(val.clone())
    }

    fn jb_retag_place_contents(
        &mut self,
        kind: RetagKind,
        place: &PlaceTy<'tcx>,
    ) -> InterpResult<'tcx> {
        interp_ok(())
    }

    fn jb_protect_place(&mut self, place: &MPlaceTy<'tcx>) -> InterpResult<'tcx, MPlaceTy<'tcx>> {
        let this = self.eval_context_mut();
        return interp_ok(place.clone());
        let (id, s, x) = this.ptr_get_alloc_id(place.ptr(), 0)?;
        let extra = this.get_alloc_extra(id)?;
        let cell = extra.borrow_tracker_jb();
        let mut borrow_tracker = cell.borrow_mut();
        borrow_tracker.protect_place(place)
    }

    fn jb_expose_tag(&self, alloc_id: AllocId, tag: BorTag) -> InterpResult<'tcx> {
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
                alloc_extra.borrow_tracker_tb().borrow_mut().expose_tag(tag);
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
