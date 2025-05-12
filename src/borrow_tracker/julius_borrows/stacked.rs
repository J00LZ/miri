use rustc_abi::Size;
use rustc_const_eval::interpret::{interp_ok, AllocId};

use super::{Checker, CheckerBuilder};
use crate::{BorTag, MemoryKind};

pub struct BasicStackCheckerBuilder;

#[derive(Debug, Clone)]
pub struct BasicStackChecker {
    root: BorTag,
    
}

impl CheckerBuilder for BasicStackCheckerBuilder {
    type Checker = BasicStackChecker;

    fn build_checker(
        &self,
        id: AllocId,
        size: Size,
        kind: MemoryKind,
        tag: BorTag,
    ) -> Self::Checker {
        BasicStackChecker { root: tag }
    }
}

impl Checker for BasicStackChecker {
    fn check_access<'ecx, 'tcx>(
            &mut self,
            mode: crate::AccessKind,
            alloc_id: AllocId,
            tag: BorTag,
            range: rustc_const_eval::interpret::AllocRange,
            machine: &'ecx crate::MiriMachine<'tcx>,
        ) -> rustc_const_eval::interpret::InterpResult<'tcx>
        where
            'tcx: 'ecx, {
        println!("Checking access: {:?} {:?} {:?}", mode, alloc_id, tag);

        interp_ok(())
    }
}
