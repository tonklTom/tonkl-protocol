// Absolute minimum circuit - no hashing at all
fn main(x: pub Field, y: Field) {
    assert(x + y != 0, "sum must be nonzero");
}
