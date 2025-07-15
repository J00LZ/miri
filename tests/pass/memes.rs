fn main() {
    let mut b = 10;
    let mut f = Foo { a: 20, b: &mut b };
    foo(&mut f, 42);
    let c = 10;
    foo_simple(&c);
}

fn foo_simple(x: &i32) {
    extern "Rust" {
        fn miripbt_foo_simple(format: &[&'static str], x: &&i32);
    }

    unsafe {
        miripbt_foo_simple(&["x"], &&x);
    }

    let x = 10;

    if x % 2 == 0 {
        bar(&x)
    }

    println!("{x}");

    println!("output is {x}")
}

fn bar(x: *const i32) {
    // set value of x
    let y = x as *mut i32;
    unsafe {
        *y = 20;
    }
}

#[derive(Debug)]
struct Foo {
    a: i32,
    b: *mut i32,
}

fn foo(f: &mut Foo, x: i32) -> i32 {
    extern "Rust" {
        fn miripbt_foo(args: &[&'static str], f: &&mut Foo, x: &i32);
    }
    unsafe { miripbt_foo(&["f", "x"], &f, &x) }
    println!("{f:?}, {x}");
    // This function is marked with the `miripbt` marker.
    // It will be processed by the miripbt tool.
    f.a + unsafe { *f.b } + x
}
