fn simulate() {
    const KEY = "key";

    let x = 1000;

    // simulate do..while using loop

    debug("start simulation");

    loop {
        storage_set([KEY, "2"], "2");

        x -= 1;

        if x <= 0 { break; }
    }

    debug("end simulation");
}
