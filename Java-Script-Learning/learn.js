var button=document.querySelector("button");
var box=document.getElementById("changeMe");


button.onclick=function changeColor(){
    box.style.background="blue";
}

//button.ondblclick=function ChangeFarbe(){
//    box.style.background="green";
// }


function ChangeFarbe(){
    if (box.style.background=="Blue"){
        box.style.background="Pink";
    }else{
        box.style.background="Brown";

    }
   
}

function Blue(){
    if (box.style.background=="blue"){
        box.style.background="Pink";

    }else{
        box.style.background="yellow";
    }
    
}
