import "sim" as sim;

const TEST = "abcd";
const KEY = "key";

fn deploy() {
    print("deploy called");
}


fn handle() {
    print("handle called");

    sim::simulate();
}


fn query() {
    print("query called");
}


// Testing (ignore me)
fn simple() {
    storage_set(KEY, "2");
}
