use std::embedded_curve_ops::{EmbeddedCurvePoint, EmbeddedCurveScalar, multi_scalar_mul};

fn main(sk: Field) -> pub (Field, Field) {
    let scalar = EmbeddedCurveScalar::from_field(sk);
    let pk = multi_scalar_mul([EmbeddedCurvePoint::generator()], [scalar]);
    (pk.x, pk.y)
}
