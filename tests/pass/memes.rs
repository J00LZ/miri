fn main() {
    let x = "memes";
    test(x);
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

#[cfg(not(miripbt))]
#[cfg_attr(miripbt_gen, miripbt::tool)]
fn test(foo: &str) {
    println!("test: {}", foo);
}
#[cfg(miripbt)]
fn test(foo: &str) {
    #[cfg(not(miripbt))]
    unsafe extern "Rust" {
        fn miripbt_test(names: &[&str], foo: &&str);

        fn miripbtexit();

    }
    #[cfg(miripbt)]
    extern "Rust" {
        fn miripbt_test(names: &[&str], foo: &&str);

        fn miripbtexit();

    }
    unsafe {
        miripbt_test(&["foo"], &foo);
    }
    let res = {
        println!("test: {}", foo);
    };
    unsafe {
        miripbtexit();
    }
    res
}
