fn main() {
    let mut x = 10;
    let foo = &mut x as *mut i32;
    let bar = &mut x as *mut i32;

    let foo = unsafe { &mut *foo };
    let bar = unsafe { &mut *bar };

    *foo = 20;
    *bar = 30;
    assert_eq!(*foo, 30);
    assert_eq!(*bar, 30);
    assert_eq!(x, 30);
}
