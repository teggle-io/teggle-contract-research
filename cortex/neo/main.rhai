import "sim" as sim;

fn deploy() {
    print("deploy called");
}


fn handle() {
    print("handle called");
    print(ENV);

    sim::simulate();
}


fn query() {
    print("query called");
}
