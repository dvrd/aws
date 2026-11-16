package main
import "core:encoding/json"
import "core:fmt"
import "core:net"
import "core:time"
main :: proc() {
    listener,error:=net.listen_tcp({net.IP4_Loopback,0});assert(error==nil);defer net.close(listener)
    assert(net.set_blocking(listener,false)==.None)
    endpoint,bound:=net.bound_endpoint(listener);assert(bound==.None)
    fmt.printf("ready %d\n",endpoint.port)
    started:=time.tick_now();socket:net.TCP_Socket;accepted:=false
    for time.tick_since(started)<5*time.Second {
        connection,_,failure:=net.accept_tcp(listener)
        if failure==nil {socket=connection;accepted=true;break}
        assert(failure==.Would_Block);time.sleep(time.Millisecond)
    }
    assert(accepted)
    assert(net.set_blocking(socket,true)==.None)
    assert(net.set_option(socket,.Receive_Timeout,2*time.Second)==nil)
    hello:[6]u8;used:=0
    for used<len(hello) {n,received:=net.recv_tcp(socket,hello[used:]);assert(received==.None&&n>0);used+=n}
    net.close(socket)
    valid:=hello[0]==22&&hello[1]==3&&hello[5]==1
    started=time.tick_now()
    for time.tick_since(started)<200*time.Millisecond {
        extra,_,failure:=net.accept_tcp(listener)
        if failure==nil {net.close(extra);assert(false,"extra native connection")}
        assert(failure==.Would_Block);time.sleep(time.Millisecond)
    }
    data,encoded:=json.marshal(struct{accepted_connections:int,tls_client_hello_seen:bool}{1,valid});assert(encoded==nil);defer delete(data)
    fmt.println(string(data));assert(valid)
}
