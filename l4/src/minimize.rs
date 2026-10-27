//! [`Formula`] to a minimal sum of products, through Espresso.
//!
//! The formula is first built as a BDD, which canonicalises it, so the cover
//! handed to Espresso does not depend on how the expression was written. The
//! ON-set is `formula and not exclusions`, the don't-care set the exclusions
//! themselves: Espresso may cover an impossible combination or not, whichever
//! gives fewer cubes.

use crate::LowerError;
use crate::formula::Formula;
use espresso_logic::bdd::{Bdd, BddBuilder, Brand, ManagerCell};
use espresso_logic::{Anonymous, Cover, CoverType, Cube, CubeType, Minimizable, Symbol};
use std::collections::HashMap;

/// One product term: `Some(v)` requires atom `i` to be `v`, `None` leaves it
/// free.
pub(crate) type Literals = Vec<Option<bool>>;

pub(crate) fn minimize(
    formula: &Formula,
    exclusions: &Formula,
    vars: usize,
) -> Result<Vec<Literals>, LowerError> {
    let builder = espresso_logic::bdd_builder!();
    let dc = to_bdd(exclusions, &builder);
    let on = to_bdd(formula, &builder).and(&dc.not());

    if on.is_contradiction() {
        return Ok(Vec::new());
    }
    if on.or(&dc).is_tautology() {
        return Ok(vec![vec![None; vars]]);
    }

    let names: Vec<String> = (0..vars).map(var_name).collect();
    let positions: HashMap<&str, usize> = names
        .iter()
        .enumerate()
        .map(|(i, name)| (name.as_str(), i))
        .collect();

    let mut cover = Cover::anonymous(CoverType::FD);
    push_cubes(
        &mut cover,
        &on.cover_over(&names),
        CubeType::F,
        &positions,
        vars,
    );
    push_cubes(
        &mut cover,
        &dc.cover_over(&names),
        CubeType::D,
        &positions,
        vars,
    );

    let minimized = cover
        .try_minimize()
        .map_err(|err| LowerError::Minimization(err.to_string()))?;

    Ok(minimized
        .cubes()
        .filter(|cube| cube.cube_type() == CubeType::F)
        .map(|cube| (0..vars).map(|i| cube.inputs().value_at(i)).collect())
        .collect())
}

fn var_name(index: usize) -> String {
    format!("a{index}")
}

fn to_bdd<B: Brand, C: ManagerCell>(formula: &Formula, builder: &BddBuilder<B, C>) -> Bdd<B, C> {
    match formula {
        Formula::Const(value) => builder.constant(*value),
        Formula::Var(index) => builder.var(var_name(*index)),
        Formula::Not(inner) => to_bdd(inner, builder).not(),
        Formula::And(items) => items
            .iter()
            .map(|item| to_bdd(item, builder))
            .reduce(|acc, item| acc.and(&item))
            .unwrap_or_else(|| builder.constant(true)),
        Formula::Or(items) => items
            .iter()
            .map(|item| to_bdd(item, builder))
            .reduce(|acc, item| acc.or(&item))
            .unwrap_or_else(|| builder.constant(false)),
        Formula::Xor(a, b) => to_bdd(a, builder).xor(&to_bdd(b, builder)),
    }
}

/// Copies `source`'s cubes into `target` as `kind`, reordering columns from
/// `source`'s header to atom order.
fn push_cubes(
    target: &mut Cover<Anonymous, Anonymous>,
    source: &Cover<Symbol, Anonymous>,
    kind: CubeType,
    positions: &HashMap<&str, usize>,
    vars: usize,
) {
    let columns: Vec<usize> = source
        .input_labels()
        .iter()
        .map(|label| positions[label.as_ref()])
        .collect();
    for cube in source.cubes() {
        let mut values = vec![None; vars];
        for (column, &position) in columns.iter().enumerate() {
            values[position] = cube.inputs().value_at(column);
        }
        target.push(Cube::anonymous(&values, &[true], kind));
    }
}

#[cfg(all(test, not(miri)))]
mod tests {
    use super::*;

    fn eval_cubes(cubes: &[Literals], assignment: &[bool]) -> bool {
        cubes.iter().any(|cube| {
            cube.iter()
                .zip(assignment)
                .all(|(literal, &value)| literal.is_none_or(|l| l == value))
        })
    }

    /// The minimised cover must agree with the formula on every assignment
    /// the exclusions allow.
    #[test]
    fn minimised_cover_is_equivalent_off_the_dont_cares() {
        let v = Formula::Var;
        let formula = Formula::or([
            Formula::and([v(0), v(1)]),
            Formula::and([v(0), Formula::not(v(1)), v(2)]),
            Formula::xor(v(2), v(3)),
        ]);
        let exclusions = Formula::and([v(1), v(3)]);
        let cubes = minimize(&formula, &exclusions, 4).unwrap();

        for bits in 0..16u8 {
            let assignment: Vec<bool> = (0..4).map(|i| bits & (1 << i) != 0).collect();
            if exclusions.eval(&assignment) {
                continue;
            }
            assert_eq!(
                eval_cubes(&cubes, &assignment),
                formula.eval(&assignment),
                "assignment {assignment:?}"
            );
        }
    }

    /// Constant formulas must not reach Espresso with zero columns.
    #[test]
    fn constants() {
        assert!(
            minimize(&Formula::Const(false), &Formula::Const(false), 0)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            minimize(&Formula::Const(true), &Formula::Const(false), 2).unwrap(),
            vec![vec![None, None]]
        );
    }
}
