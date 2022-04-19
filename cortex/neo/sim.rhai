fn simulate() {
    let x = 1000;

    // simulate do..while using loop

    debug("start simulation");

    loop {
        storage_set(`key.${x}`, x.to_string());

        x -= 1;

        if x <= 0 { break; }
    }

    debug("end simulation");
}
