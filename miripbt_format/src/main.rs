use std::collections::HashMap;

use miripbt_format::communication::Mutability;

fn main() {
    let foo = Mutability {
        mutable: miripbt_format::communication::MutabilityKind::Mutable,
        children: {
            let mut map = HashMap::new();
            map.insert(
                "child1".to_string(),
                Mutability {
                    mutable: miripbt_format::communication::MutabilityKind::Immutable,
                    children: HashMap::new(),
                },
            );

            map.insert(
                "child2".to_string(),
                Mutability {
                    mutable: miripbt_format::communication::MutabilityKind::Mutable,
                    children: HashMap::new(),
                },
            );

            map
        },
    };
    let foo = {
        let mut map = HashMap::new();
        map.insert("foo".to_string(), foo);
        map
    };
    let permutations = miripbt_format::test::flatten_mutabilities(foo);
    for perm in permutations {
        println!("{:?}", perm);
    }
}
