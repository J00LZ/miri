use std::{borrow::Cow, collections::HashMap, str::FromStr};

use miripbt_format::{
    communication::{ResponseBody, Value},
    PrimitiveType, TypeRef, TypeRefType,
};
use nix::{
    sys::wait::{waitpid, WaitStatus},
    unistd::ForkResult,
};
use rustc_apfloat::ieee::{Double, Single};
use rustc_ast::Mutability;
use rustc_const_eval::interpret::{
    AllocId, AllocMap, Allocation, CheckInAllocMsg, GlobalAlloc, MPlaceTy, Machine, MemoryKind,
    Projectable,
};
use rustc_middle::{throw_ub, throw_unsup};
use rustc_target::abi::VariantIdx;

use crate::{
    helpers::{EvalContextExt, ToHost},
    pbt::Pbt,
    InterpCx, InterpResult, MiriInterpCxExt, MiriMachine, OpTy, Scalar,
};

pub trait PbtEvalCtx<'tcx>: MiriInterpCxExt<'tcx> {
    fn run_pbt(&mut self, func_name: &str, args: &[OpTy<'tcx>]) -> InterpResult<'tcx> {
        println!("running for {}", func_name);
        let this = self.eval_context_mut();
        if let Some(mut pbt) = { this.machine.pbt.as_ref().cloned() } {
            print!("we have pbt data, and the following functions: ");
            for f in &pbt.format.functions {
                print!("{} ", f.name);
            }
            println!();

            if let Some(f) = pbt.format.functions.iter().find(|f| f.name == func_name).cloned() {
                println!("found function {}", f.name);
                if f.args.is_empty() {
                    return Ok(());
                }

                let elements = modify_args(this, args, &f)?;

                let mut res = HashMap::<i32, i32>::new();
                let mut is_main = true;
                for _ in 0..10 {
                    let ResponseBody::Data(body) =
                        pbt.write(miripbt_format::communication::RequestBody::Request(
                            f.name.clone(),
                            miripbt_format::communication::PBTType::Values,
                        ))
                    else {
                        return Ok(());
                    };

                    set_values(this, &elements, args, &body, &pbt, func_name)?;

                    match unsafe { nix::unistd::fork() } {
                        Ok(ForkResult::Parent { child }) => {
                            let WaitStatus::Exited(_pid, code) = waitpid(child, None).unwrap()
                            else {
                                let e = res.entry(-41).or_default();
                                *e = e.saturating_add(1);
                                continue;
                            };
                            println!("Recieved code {code}!");
                            let e = res.entry(code).or_default();
                            *e = e.saturating_add(1);
                            if code == 41 {
                                match unsafe { nix::unistd::fork() } {
                                    Ok(ForkResult::Parent { child }) => {
                                        let WaitStatus::Exited(_pid, code) =
                                            waitpid(child, None).unwrap()
                                        else {
                                            continue;
                                        };
                                        if code != 0 {
                                            pbt.has_failed
                                                .store(true, std::sync::atomic::Ordering::SeqCst);
                                        }
                                    }
                                    Ok(ForkResult::Child) => {
                                        is_main = false;
                                        this.machine.borrow_tracker = None;

                                        break;
                                    }
                                    Err(_) => panic!("Fork failed!!"),
                                }
                                if pbt.stop_after_first {
                                    break;
                                }
                            }
                        }
                        Ok(ForkResult::Child) => {
                            is_main = false;
                            break;
                        }
                        Err(_) => panic!("Fork failed!!"),
                    }
                }
                if is_main {
                    println!("Final result:");
                    for (code, count) in res {
                        println!("Code {code} was returned {count} times");
                    }
                    println!("And ran 10 times total");
                    std::process::exit(0);
                }
            }
        }

        Ok(())
    }

    fn run_pbt_exit(&mut self, func_name: &str, args: &[OpTy<'tcx>]) -> InterpResult<'tcx> {
        println!("running exit for {}", func_name);
        let this = self.eval_context_mut();
        let mut err_code = 0;
        if let Some(pbt) = { this.machine.pbt.as_ref().cloned() } {
            if let Some(f) = pbt.format.functions.iter().find(|f| f.name == func_name).cloned() {
                println!("found function {}", f.name);
                if f.args.is_empty() {
                    return Ok(());
                }

                let elements = modify_args(this, args, &f)?;
                let mut after_exec = HashMap::new();
                for (arg_name, (idx, arg)) in &elements {
                    #[allow(clippy::cast_possible_truncation)]
                    let actual_arg = &args[*idx as usize];
                    let mut target = this.deref_pointer(actual_arg)?;

                    match arg.kind {
                        miripbt_format::TypeRefKind::Value | miripbt_format::TypeRefKind::Other => {
                        }
                        miripbt_format::TypeRefKind::Ref
                        | miripbt_format::TypeRefKind::RefMut
                        | miripbt_format::TypeRefKind::Ptr
                        | miripbt_format::TypeRefKind::PtrMut => {
                            target = this.deref_pointer(&target)?;
                        }
                    }

                    after_exec.insert(
                        arg_name.to_string(),
                        arg_to_pbt_value(this, &target, &arg.type_ref, &pbt)?,
                    );
                }
                match pbt.are_equal(func_name, Value::Map(after_exec)) {
                    Ok(v) =>
                        for diag in &v {
                            err_code = 41;
                            eprintln!("{diag}");
                        },
                    Err(e) => {
                        eprintln!("Comparison failed: {e}")
                    }
                }
            }
        }

        std::process::exit(err_code)
    }
}

fn set_values<'tcx>(
    this: &mut InterpCx<'tcx, MiriMachine<'tcx>>,
    elements: &HashMap<String, (u64, &TypeRef)>,
    args: &[OpTy<'tcx>],
    body: &HashMap<String, Value>,
    pbt: &Pbt,
    func_name: &str,
) -> InterpResult<'tcx> {
    let mut before_exec = HashMap::new();

    for (arg_name, (idx, arg)) in elements {
        #[allow(clippy::cast_possible_truncation)]
        let actual_arg = &args[*idx as usize];
        let body = body.get(arg_name).cloned().unwrap_or(Value::Unit);
        let mut target = this.deref_pointer(actual_arg)?;

        match arg.kind {
            miripbt_format::TypeRefKind::Value | miripbt_format::TypeRefKind::Other => {}
            miripbt_format::TypeRefKind::Ref
            | miripbt_format::TypeRefKind::RefMut
            | miripbt_format::TypeRefKind::Ptr
            | miripbt_format::TypeRefKind::PtrMut => {
                target = this.deref_pointer(&target)?;
            }
        }
        update_single_value(this, &target, arg, body, &pbt)?;

        before_exec
            .insert(arg_name.to_string(), arg_to_pbt_value(this, &target, &arg.type_ref, &pbt)?);
    }
    pbt.set_prev(func_name, Value::Map(before_exec));
    Ok(())
}

fn modify_args<'tcx, 'f>(
    this: &InterpCx<'tcx, MiriMachine<'tcx>>,
    args: &[OpTy<'tcx>],
    f: &'f miripbt_format::Function,
) -> InterpResult<'tcx, HashMap<String, (u64, &'f TypeRef)>> {
    let array = this.deref_pointer(&args[0])?;
    let mut array = this.project_array_fields(&array)?;
    let mut elements = HashMap::new();
    while let Ok(Some((a, b))) = array.next(this) {
        let d = this.deref_pointer(&b)?;
        let s = this.read_str(&d)?.to_owned();
        if let Some(tr) = f.args.get(&s) {
            elements.insert(s, (a.saturating_add(1), tr));
        }
    }

    Ok(elements)
}

impl<'tcx> PbtEvalCtx<'tcx> for crate::MiriInterpCx<'tcx> {}

#[allow(clippy::cast_possible_truncation)]
fn update_single_value<'tcx>(
    this: &mut InterpCx<'tcx, MiriMachine<'tcx>>,
    target: &MPlaceTy<'tcx, crate::machine::Provenance>,
    arg: &TypeRef,
    body: Value,
    pbt: &Pbt,
) -> InterpResult<'tcx> {
    match &arg.type_ref {
        miripbt_format::TypeRefType::Primitive(primitive_type) =>
            match (primitive_type, body) {
                (miripbt_format::PrimitiveType::Bool, Value::Bool(b)) => {
                    modify_value(this, target, |this, target| {
                        this.write_scalar(Scalar::from_bool(b), target)
                    })?;
                }
                (miripbt_format::PrimitiveType::Isize, Value::INum(i)) =>
                    modify_value(this, target, |this, target| {
                        this.write_scalar(Scalar::from_target_isize(i as i64, this), target)
                    })?,
                (miripbt_format::PrimitiveType::I8, Value::INum(i)) =>
                    modify_value(this, target, |this, target| {
                        this.write_scalar(Scalar::from_i8(i as i8), target)
                    })?,
                (miripbt_format::PrimitiveType::I16, Value::INum(i)) =>
                    modify_value(this, target, |this, target| {
                        this.write_scalar(Scalar::from_i16(i as i16), target)
                    })?,
                (miripbt_format::PrimitiveType::I32, Value::INum(i)) =>
                    modify_value(this, target, |this, target| {
                        this.write_scalar(Scalar::from_i32(i as i32), target)
                    })?,
                (miripbt_format::PrimitiveType::I64, Value::INum(i)) =>
                    modify_value(this, target, |this, target| {
                        this.write_scalar(Scalar::from_i64(i as i64), target)
                    })?,
                (miripbt_format::PrimitiveType::I128, Value::INum(i)) =>
                    modify_value(this, target, |this, target| {
                        this.write_scalar(Scalar::from_i128(i), target)
                    })?,
                (miripbt_format::PrimitiveType::Usize, Value::UNum(u)) =>
                    modify_value(this, target, |this, target| {
                        this.write_scalar(Scalar::from_target_usize(u as u64, this), target)
                    })?,
                (miripbt_format::PrimitiveType::U8, Value::UNum(u)) =>
                    modify_value(this, target, |this, target| {
                        this.write_scalar(Scalar::from_u8(u as u8), target)
                    })?,
                (miripbt_format::PrimitiveType::U16, Value::UNum(u)) =>
                    modify_value(this, target, |this, target| {
                        this.write_scalar(Scalar::from_u16(u as u16), target)
                    })?,
                (miripbt_format::PrimitiveType::U32, Value::UNum(u)) =>
                    modify_value(this, target, |this, target| {
                        this.write_scalar(Scalar::from_u32(u as u32), target)
                    })?,
                (miripbt_format::PrimitiveType::U64, Value::UNum(u)) =>
                    modify_value(this, target, |this, target| {
                        this.write_scalar(Scalar::from_u64(u as u64), target)
                    })?,
                (miripbt_format::PrimitiveType::U128, Value::UNum(u)) =>
                    modify_value(this, target, |this, target| {
                        this.write_scalar(Scalar::from_u128(u), target)
                    })?,

                (miripbt_format::PrimitiveType::F16, Value::Float(_)) => todo!(),
                (miripbt_format::PrimitiveType::F32, Value::Float(f)) =>
                    modify_value(this, target, |this, target| {
                        this.write_scalar(
                            Scalar::from_f32(Single::from_str(&format!("{f}")).unwrap()),
                            target,
                        )
                    })?,
                (miripbt_format::PrimitiveType::F64, Value::Float(f)) =>
                    modify_value(this, target, |this, target| {
                        this.write_scalar(
                            Scalar::from_f64(Double::from_str(&format!("{f}")).unwrap()),
                            target,
                        )
                    })?,
                (miripbt_format::PrimitiveType::F128, Value::Float(_)) => todo!(),

                (miripbt_format::PrimitiveType::Str(string_type), Value::String(s)) =>
                    match string_type {
                        miripbt_format::StringType::Str => {
                            modify_value(this, target, |this, target| {
                                let len = target.len(this)? as usize;
                                let mut bytes = s.as_bytes().to_vec();
                                let ptr = target.ptr();
                                bytes.resize(len, 0x41);
                                this.write_bytes_ptr(ptr, bytes)?;
                                Ok(())
                            })?;
                        }
                        miripbt_format::StringType::String => {}
                        miripbt_format::StringType::CStr => {
                            modify_value(this, target, |this, target| {
                                let ptr = target.ptr();
                                let len = this.read_c_str(ptr)?.len().saturating_sub(1);
                                let mut bytes = s.as_bytes().to_vec();
                                bytes.resize(len, 0x41);
                                this.write_c_str(&bytes, ptr, bytes.len() as u64)?;
                                Ok(())
                            })?;
                        }
                        miripbt_format::StringType::CString => {}
                    },

                (miripbt_format::PrimitiveType::Char, Value::Char(c)) => {
                    modify_value(this, target, |this, target| {
                        this.write_scalar(Scalar::from_char(c), target)
                    })?;
                }

                (miripbt_format::PrimitiveType::Unit, Value::Unit) => {}
                (miripbt_format::PrimitiveType::Never, Value::Never) => {}
                _ => unreachable!(),
            },
        miripbt_format::TypeRefType::Type(s) =>
            if let Some(t) = pbt.format.find_type(s).cloned() {
                match t {
                    miripbt_format::Type::Struct(s) => {
                        let Value::Map(mut m) = body else { return Ok(()) };
                        for (name, arg) in &s.fields {
                            let mut target = this.project_field_named(target, name)?;
                            match arg.kind {
                                miripbt_format::TypeRefKind::Value
                                | miripbt_format::TypeRefKind::Other => {}
                                miripbt_format::TypeRefKind::Ref
                                | miripbt_format::TypeRefKind::RefMut
                                | miripbt_format::TypeRefKind::Ptr
                                | miripbt_format::TypeRefKind::PtrMut => {
                                    target = this.deref_pointer(&target)?;
                                }
                            }
                            let Some(body) = m.remove(name) else {
                                continue;
                            };
                            update_single_value(this, &target, arg, body, pbt)?;
                        }
                    }
                    miripbt_format::Type::Enum(e) => {
                        let Value::EnumVariant(m) = body else { return Ok(()) };
                        let var = e.variants[&m];
                        modify_value(this, target, |this, target| {
                            this.write_discriminant(VariantIdx::from_u32(var), target)
                        })?;
                    }
                }
            },
        miripbt_format::TypeRefType::Array { .. } => {}
    }
    Ok(())
}

fn modify_value<'tcx, R>(
    this: &mut InterpCx<'tcx, MiriMachine<'tcx>>,
    dest: &MPlaceTy<'tcx, crate::machine::Provenance>,

    set_value: impl FnOnce(
        &mut InterpCx<'tcx, MiriMachine<'tcx>>,
        &MPlaceTy<'tcx, crate::machine::Provenance>,
    ) -> InterpResult<'tcx, R>,
) -> InterpResult<'tcx, R> {
    let (id, _, _) = this.ptr_get_alloc_id(dest.ptr())?;
    let bt;
    let m_bt;
    let old_mutability;
    {
        let extra = get_alloc_raw_mut(this, id)?;
        old_mutability = extra.mutability;
        extra.mutability = Mutability::Mut;
        let extra = &mut extra.extra;
        bt = extra.borrow_tracker.take();
        m_bt = this.machine.borrow_tracker.take();
    }
    let res = set_value(this, dest)?;
    {
        let extra = get_alloc_raw_mut(this, id)?;
        extra.mutability = old_mutability;
        let extra = &mut extra.extra;
        extra.borrow_tracker = bt;
        this.machine.borrow_tracker = m_bt;
    }
    Ok(res)
}

// all below are borrowed from `memory.rs` in `rustc_const_eval`, I need to be able to force the mutability of an allocation
fn get_alloc_raw_mut<'a, 'tcx, M: Machine<'tcx>>(
    this: &'a mut InterpCx<'tcx, M>,
    id: AllocId,
) -> InterpResult<'tcx, &'a mut Allocation<M::Provenance, M::AllocExtra, M::Bytes>> {
    // We have "NLL problem case #3" here, which cannot be worked around without loss of
    // efficiency even for the common case where the key is in the map.
    // <https://rust-lang.github.io/rfcs/2094-nll.html#problem-case-3-conditional-control-flow-across-functions>
    // (Cannot use `get_mut_or` since `get_global_alloc` needs `&self`.)
    if amap(this).get_mut(id).is_none() {
        // Slow path.
        // Allocation not found locally, go look global.
        let alloc = get_global_alloc(this, id, /*is_write*/ false)?;
        let kind = M::GLOBAL_KIND.expect(
            "I got a global allocation that I have to copy but the machine does \
                    not expect that to happen",
        );
        amap(this).insert(id, (MemoryKind::Machine(kind), alloc.into_owned()));
    }

    let (_kind, alloc) = amap(this).get_mut(id).unwrap();
    // if alloc.mutability.is_not() {
    //     throw_ub!(WriteToReadOnly(id))
    // }
    Ok(alloc)
}

#[allow(mutable_transmutes, clippy::mut_from_ref)]
fn amap<'a, 'tcx, M: Machine<'tcx>>(this: &'a InterpCx<'tcx, M>) -> &'a mut M::MemoryMap {
    let map = this.memory.alloc_map();
    // very safe transmute
    unsafe { std::mem::transmute::<&M::MemoryMap, &mut M::MemoryMap>(map) }
}

fn get_global_alloc<'a, 'tcx, M: Machine<'tcx>>(
    this: &'a InterpCx<'tcx, M>,
    id: AllocId,
    is_write: bool,
) -> InterpResult<'tcx, Cow<'tcx, Allocation<M::Provenance, M::AllocExtra, M::Bytes>>> {
    let (alloc, def_id) = match this.tcx.try_get_global_alloc(id) {
        Some(GlobalAlloc::Memory(mem)) => {
            // Memory of a constant or promoted or anonymous memory referenced by a static.
            (mem, None)
        }
        Some(GlobalAlloc::Function(..)) => throw_ub!(DerefFunctionPointer(id)),
        Some(GlobalAlloc::VTable(..)) => throw_ub!(DerefVTablePointer(id)),
        None => throw_ub!(PointerUseAfterFree(id, CheckInAllocMsg::MemoryAccessTest)),
        Some(GlobalAlloc::Static(def_id)) => {
            assert!(this.tcx.is_static(def_id));
            // Thread-local statics do not have a constant address. They *must* be accessed via
            // `ThreadLocalRef`; we can never have a pointer to them as a regular constant value.
            assert!(!this.tcx.is_thread_local_static(def_id));
            // Notice that every static has two `AllocId` that will resolve to the same
            // thing here: one maps to `GlobalAlloc::Static`, this is the "lazy" ID,
            // and the other one is maps to `GlobalAlloc::Memory`, this is returned by
            // `eval_static_initializer` and it is the "resolved" ID.
            // The resolved ID is never used by the interpreted program, it is hidden.
            // This is relied upon for soundness of const-patterns; a pointer to the resolved
            // ID would "sidestep" the checks that make sure consts do not point to statics!
            // The `GlobalAlloc::Memory` branch here is still reachable though; when a static
            // contains a reference to memory that was created during its evaluation (i.e., not
            // to another static), those inner references only exist in "resolved" form.
            if this.tcx.is_foreign_item(def_id) {
                // This is unreachable in Miri, but can happen in CTFE where we actually *do* support
                // referencing arbitrary (declared) extern statics.
                throw_unsup!(ExternStatic(def_id));
            }

            // We don't give a span -- statics don't need that, they cannot be generic or associated.
            let val = this.ctfe_query(|tcx| tcx.eval_static_initializer(def_id))?;
            (val, Some(def_id))
        }
    };
    M::before_access_global(this.tcx, &this.machine, id, alloc, def_id, is_write)?;
    // We got tcx memory. Let the machine initialize its "extra" stuff.
    M::adjust_global_allocation(
        this,
        id, // always use the ID we got as input, not the "hidden" one.
        alloc.inner(),
    )
}

fn arg_to_pbt_value<'tcx>(
    this: &mut InterpCx<'tcx, MiriMachine<'tcx>>,
    target: &MPlaceTy<'tcx, crate::machine::Provenance>,
    arg: &TypeRefType,
    pbt: &Pbt,
) -> InterpResult<'tcx, Value> {
    println!("Attempting to convert {:?} to a value", arg);
    match &arg {
        miripbt_format::TypeRefType::Primitive(PrimitiveType::Str(s)) =>
            match s {
                miripbt_format::StringType::Str => {
                    let s = this.read_str(target)?;
                    Ok(Value::String(s.to_string()))
                }
                miripbt_format::StringType::String => todo!(),
                miripbt_format::StringType::CStr => {
                    let ptr = this.read_pointer(target)?;
                    let cstr = this.read_c_str(ptr)?;
                    let s = String::from_utf8_lossy(cstr);
                    Ok(Value::String(s.to_string()))
                }
                miripbt_format::StringType::CString => todo!(),
            },
        miripbt_format::TypeRefType::Primitive(primitive_type) =>
            handle_primitive(this, primitive_type, this.read_scalar(target)?),
        miripbt_format::TypeRefType::Type(typ) =>
            if let Some(ty) = pbt.format.find_type(typ) {
                match ty {
                    miripbt_format::Type::Struct(s) => {
                        let mut map = HashMap::new();

                        for (k, v) in &s.fields {
                            println!("Running for field {}, {:?}", k, v);
                            let mut target = this.project_field_named(target, k)?;
                            match v.kind {
                                miripbt_format::TypeRefKind::Value
                                | miripbt_format::TypeRefKind::Other => {}
                                miripbt_format::TypeRefKind::Ref
                                | miripbt_format::TypeRefKind::RefMut
                                | miripbt_format::TypeRefKind::Ptr
                                | miripbt_format::TypeRefKind::PtrMut => {
                                    target = this.deref_pointer(&target)?;
                                }
                            }
                            map.insert(
                                k.clone(),
                                arg_to_pbt_value(this, &target, &v.type_ref, pbt)?,
                            );
                        }

                        Ok(Value::Map(map))
                    }
                    miripbt_format::Type::Enum(e) => {
                        println!("Running for enum {}", e.name);
                        let enum_var = this.read_discriminant(target)?;

                        let var = e
                            .variants
                            .iter()
                            .find_map(|(k, v)| (*v == enum_var.as_u32()).then(|| k.to_string()))
                            .unwrap_or_default();
                        Ok(Value::EnumVariant(var))
                    }
                }
            } else {
                Ok(Value::Never)
            },
        miripbt_format::TypeRefType::Array { array_type, element_type, .. } =>
            match array_type {
                miripbt_format::ArrayType::Vec => todo!(),
                miripbt_format::ArrayType::Array => {
                    let mut data = vec![];
                    while let Some((_, mut target)) =
                        this.project_array_fields(target)?.next(this)?
                    {
                        match element_type.kind {
                            miripbt_format::TypeRefKind::Value
                            | miripbt_format::TypeRefKind::Other => {}
                            miripbt_format::TypeRefKind::Ref
                            | miripbt_format::TypeRefKind::RefMut
                            | miripbt_format::TypeRefKind::Ptr
                            | miripbt_format::TypeRefKind::PtrMut => {
                                target = this.deref_pointer(&target)?;
                            }
                        }
                        data.push(arg_to_pbt_value(this, &target, &element_type.type_ref, pbt));
                    }

                    todo!()
                }
            },
    }
}

/// Handle all primitives except a string
fn handle_primitive<'tcx>(
    ctx: &InterpCx<'tcx, MiriMachine<'tcx>>,
    primitive_type: &PrimitiveType,
    scalar: Scalar,
) -> InterpResult<'tcx, Value> {
    match primitive_type {
        PrimitiveType::Bool => Ok(Value::Bool(scalar.to_bool()?)),
        PrimitiveType::Isize => Ok(Value::INum(scalar.to_target_isize(ctx)?.into())),
        PrimitiveType::I8 => Ok(Value::INum(scalar.to_i8()?.into())),
        PrimitiveType::I16 => Ok(Value::INum(scalar.to_i16()?.into())),
        PrimitiveType::I32 => Ok(Value::INum(scalar.to_i32()?.into())),
        PrimitiveType::I64 => Ok(Value::INum(scalar.to_i64()?.into())),
        PrimitiveType::I128 => Ok(Value::INum(scalar.to_i128()?)),
        PrimitiveType::Usize => Ok(Value::UNum(scalar.to_target_usize(ctx)?.into())),
        PrimitiveType::U8 => Ok(Value::UNum(scalar.to_u8()?.into())),
        PrimitiveType::U16 => Ok(Value::UNum(scalar.to_u16()?.into())),
        PrimitiveType::U32 => Ok(Value::UNum(scalar.to_u32()?.into())),
        PrimitiveType::U64 => Ok(Value::UNum(scalar.to_u64()?.into())),
        PrimitiveType::U128 => Ok(Value::UNum(scalar.to_u128()?)),
        PrimitiveType::F16 => todo!(),
        PrimitiveType::F32 => Ok(Value::Float(scalar.to_f32()?.to_host().into())),
        PrimitiveType::F64 => Ok(Value::Float(scalar.to_f64()?.to_host())),
        PrimitiveType::F128 => todo!(),
        PrimitiveType::Char => Ok(Value::Char(scalar.to_char()?)),
        PrimitiveType::Unit => Ok(Value::Unit),
        PrimitiveType::Never => Ok(Value::Never),
        _ => unreachable!(),
    }
}
