use std::collections::HashMap;

use miripbt_format::{
    communication::{ResponseBody, Value},
    TypeRef, TypeRefType,
};
use nix::{
    sys::wait::{waitpid, WaitStatus},
    unistd::ForkResult,
};
use rustc_const_eval::interpret::{MPlaceTy, Provenance};
use rustc_middle::ty::{layout::LayoutOf, Ty};

use crate::{
    helpers::EvalContextExt, pbt::Pbt, InterpCx, InterpResult, MiriInterpCxExt, MiriMachine, OpTy,
    Scalar,
};

pub trait PbtEvalCtx<'tcx>: MiriInterpCxExt<'tcx> {
    fn run_pbt(&mut self, func_name: &str, args: &[OpTy<'tcx>]) -> InterpResult<'tcx> {
        let this = self.eval_context_mut();
        if let Some(mut pbt) = { this.machine.pbt.as_ref().cloned() } {
            if let Some(f) = pbt.format.functions.iter().find(|f| f.name == func_name).cloned() {
                println!("found function {}", f.name);

                let array = this.deref_pointer(&args[0])?;
                let mut array = this.project_array_fields(&array)?;
                let mut elements = HashMap::new();
                while let Ok(Some((a, b))) = array.next(this) {
                    let d = this.deref_pointer(&b)?;
                    let s = this.read_str(&d)?.to_owned();
                    if let Some(tr) = f.args.get(&s) {
                        elements.insert(s, (a + 1, tr));
                    }
                }

                let mut res = HashMap::<i32,i32>::new();
                let mut is_main = true;
                for _ in 0..10 {
                    for (arg_name, (idx, arg)) in &elements {
                        println!("running for arg {arg_name}");
                        let actual_arg = &args[*idx as usize];
                        let ResponseBody::Data(body) =
                            pbt.write(miripbt_format::communication::RequestBody::Request(
                                arg.type_ref.clone(),
                            ))
                        else {
                            continue;
                        };
                        let mut target = this.deref_pointer(actual_arg)?;
                        println!("deref 1");
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
                        println!("deref 1");

                        update_single_value(this, target, arg, body, &mut pbt)?;
                    }
                    match unsafe { nix::unistd::fork() } {
                        Ok(ForkResult::Parent { child }) => {
                            let WaitStatus::Exited(pid, code) = waitpid(child, None).unwrap()
                            else {
                                panic!("Wait failed!!!")
                            };
                            println!("Recieved code {code}!");
                            *res.entry(code).or_default() += 1;
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
}

impl<'tcx> PbtEvalCtx<'tcx> for crate::MiriInterpCx<'tcx> {}

fn update_single_value<'tcx>(
    this: &mut InterpCx<'tcx, MiriMachine<'tcx>>,
    target: MPlaceTy<'tcx, crate::machine::Provenance>,
    arg: &TypeRef,
    body: Value,
    pbt: &mut Pbt,
) -> InterpResult<'tcx> {
    println!("{arg:?}");
    match &arg.type_ref {
        miripbt_format::TypeRefType::Primitive(primitive_type) =>
            match (primitive_type, body) {
                (miripbt_format::PrimitiveType::Bool, Value::Bool(b)) => {
                    modify_value(this, target, |this, target| {
                        this.write_scalar(Scalar::Int(b.into()), &target)
                    })?;
                }
                (miripbt_format::PrimitiveType::Isize, Value::INum(i)) =>
                    modify_value(this, target, |this, target| {
                        this.write_scalar(Scalar::Int((i as i64 as u64).into()), &target)
                    })?,
                (miripbt_format::PrimitiveType::I8, Value::INum(i)) =>
                    modify_value(this, target, |this, target| {
                        this.write_scalar(Scalar::Int((i as i8 as u8).into()), &target)
                    })?,
                (miripbt_format::PrimitiveType::I16, Value::INum(i)) =>
                    modify_value(this, target, |this, target| {
                        this.write_scalar(Scalar::Int((i as i16 as u16).into()), &target)
                    })?,
                (miripbt_format::PrimitiveType::I32, Value::INum(i)) =>
                    modify_value(this, target, |this, target| {
                        this.write_scalar(Scalar::Int((i as i32 as u32).into()), &target)
                    })?,
                (miripbt_format::PrimitiveType::I64, Value::INum(i)) =>
                    modify_value(this, target, |this, target| {
                        this.write_scalar(Scalar::Int((i as i64 as u64).into()), &target)
                    })?,
                (miripbt_format::PrimitiveType::I128, Value::INum(i)) =>
                    modify_value(this, target, |this, target| {
                        this.write_scalar(Scalar::Int((i as i128 as u128).into()), &target)
                    })?,
                (miripbt_format::PrimitiveType::Usize, Value::UNum(u)) =>
                    modify_value(this, target, |this, target| {
                        this.write_scalar(Scalar::Int((u as usize as u64).into()), &target)
                    })?,
                (miripbt_format::PrimitiveType::U8, Value::UNum(u)) =>
                    modify_value(this, target, |this, target| {
                        this.write_scalar(Scalar::Int((u as u8).into()), &target)
                    })?,
                (miripbt_format::PrimitiveType::U16, Value::UNum(u)) =>
                    modify_value(this, target, |this, target| {
                        this.write_scalar(Scalar::Int((u as u16).into()), &target)
                    })?,
                (miripbt_format::PrimitiveType::U32, Value::UNum(u)) =>
                    modify_value(this, target, |this, target| {
                        this.write_scalar(Scalar::Int((u as u32).into()), &target)
                    })?,
                (miripbt_format::PrimitiveType::U64, Value::UNum(u)) =>
                    modify_value(this, target, |this, target| {
                        this.write_scalar(Scalar::Int((u as u64).into()), &target)
                    })?,
                (miripbt_format::PrimitiveType::U128, Value::UNum(u)) =>
                    modify_value(this, target, |this, target| {
                        this.write_scalar(Scalar::Int((u as u128).into()), &target)
                    })?,

                (miripbt_format::PrimitiveType::F16, Value::Float(_)) => todo!(),
                (miripbt_format::PrimitiveType::F32, Value::Float(_)) => todo!(),
                (miripbt_format::PrimitiveType::F64, Value::Float(_)) => todo!(),
                (miripbt_format::PrimitiveType::F128, Value::Float(_)) => todo!(),

                (miripbt_format::PrimitiveType::Str, Value::String(_s)) => todo!(),

                (miripbt_format::PrimitiveType::Char, Value::Char(_)) => todo!(),

                (miripbt_format::PrimitiveType::Unit, Value::Unit) => {}
                _ => unreachable!(),
            },
        miripbt_format::TypeRefType::Struct(s) =>
            if let Some(t) = pbt.format.find_type(s).cloned() {
                let Value::Map(mut m) = body else { return Ok(()) };
                println!("got values");
                for (name, arg) in &t.fields {
                    println!("{name}");
                    let mut target = this.project_field_named(&target, name)?;
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
                    let Some(body) = m.remove(name) else {
                        continue;
                    };
                    update_single_value(this, target, arg, body, pbt)?;
                }
            },
    }
    Ok(())
}

fn modify_value<'tcx, R>(
    this: &mut InterpCx<'tcx, MiriMachine<'tcx>>,
    dest: MPlaceTy<'tcx, crate::machine::Provenance>,
    set_value: impl FnOnce(
        &mut InterpCx<'tcx, MiriMachine<'tcx>>,
        MPlaceTy<'tcx, crate::machine::Provenance>,
    ) -> InterpResult<'tcx, R>,
) -> InterpResult<'tcx, R> {
    let (id, _, _) = this.ptr_get_alloc_id(dest.ptr())?;
    let bt;
    {
        let (extra, _) = this.get_alloc_extra_mut(id)?;
        bt = extra.borrow_tracker.take();
    }
    let res = set_value(this, dest)?;
    {
        let (extra, _) = this.get_alloc_extra_mut(id)?;
        extra.borrow_tracker = bt;
    }
    Ok(res)
}
