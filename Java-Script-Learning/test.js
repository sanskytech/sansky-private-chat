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
