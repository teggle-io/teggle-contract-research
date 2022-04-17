fn handle() {
    let x = 1000;

    // simulate do..while using loop

    print("sim: start simulation");

    loop {
        storage_set(`key.${x}`, x.to_string());

        x -= 1;

        if x <= 0 { break; }
    }

    print("sim: end simulation");
    debug("sim: debug");
}
