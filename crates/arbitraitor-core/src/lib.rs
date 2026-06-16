//! State machine and invariants for the Arbitraitor pipeline
//!
//! See `.spec/` for the full specification.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

#[cfg(test)]
mod tests {
    #[test]
    fn smoke_test() {
        // Ensures the crate compiles and nextest has at least one test
        // to run on branches that don't yet have implementation code.
        let one = 1;
        assert_eq!(one, 1);
    }
}
