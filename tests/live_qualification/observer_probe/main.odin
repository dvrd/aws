package main
import "core:encoding/json"
import "core:fmt"
import "core:os"
import "core:strings"
main :: proc() {
    assert(len(os.args)==2&&strings.has_prefix(os.args[1],"https://127.0.0.1:"))
    capture:S3_Read_Observation
    context.user_ptr=&capture
    body,status,error:=observed_get(os.args[1],nil,1000,1024,context.allocator)
    defer delete(body)
    assert(error==.Unavailable&&status==0&&capture.calls==1&&capture.code==.None)
    data,encoded:=json.marshal(capture.calls);assert(encoded==nil);defer delete(data)
    fmt.println(string(data))
}
