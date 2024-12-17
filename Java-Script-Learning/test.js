console.log("hello I am just learning javascript");
// setTimeout(function() {})
setTimeout(function(){
    console.log("3 seconds have passed");

},3000)

var time=0;

var event_timer=setInterval(function(){
    time +=2;
    console.log(time + " seconds have passed");
    if (time>6){
        clearInterval(event_timer)
    }

}, 2000)


var money= 60;
var PacketM=setInterval(function(){
    money += 5;
    console.log("I have"+ money + "$ now!");
    if (money==65){
        clearInterval(PacketM);

    }
},4000)

//tell the directory that we are in
console.log(__dirname);
console.log(__filename);


function Sayhi(){
    console.log("hi");
}

Sayhi();

function Saylove(){
    console.log("love");
}
Saylove();

//function expression we do not give the function name and we put it
// in a varibale and we call that 
var Sayyes=function(){
    console.log("yes!");
}
Sayyes();

function CallFunction (fun){
    fun();
}

CallFunction(Sayyes);


function encapsuler (fun){
    fun();
}

var Boos= function(){
    console.log("Boos");
}

encapsuler(Boos);