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
    //storage_set(KEY, "2");

    // Simulate store post.
    //storage_set(["P", "dda7eccb84704b8c96114fd8c68d6ec7", "len"], "1");
    //storage_set(["P", "dda7eccb84704b8c96114fd8c68d6ec7", "0"], "{ test1: data1, test2: data2, test3: data3, test4: data4 }");

    let post_storage = storage(["P", "dda7eccb84704b8c96114fd8c68d6ec7"]);
    post_storage.set();
    //post_storage.set();
    //post_storage.set();

    //debug(ENV);
}
