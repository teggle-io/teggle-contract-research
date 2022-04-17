fn handle() {
    let x = 1000;

    // simulate do..while using loop

    loop {
        storage_set("key", "1");

        x -= 1;

        if x <= 0 { break; }
    }
}
