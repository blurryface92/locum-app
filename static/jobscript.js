let btn = document.querySelectorAll('.btn');
let model = document.querySelector('.model');
let close = document.querySelector('.close');
let childH1 = document.querySelector('#child-h1');
let subject = document.querySelector('#subject');
let files = document.querySelector('#files');
let msg = document.querySelector('textarea');
let form = document.querySelector('form');
let h1 = document.querySelectorAll('h1');
let grid = document.querySelectorAll('.grid');
btn.forEach(function(item){
    item.addEventListener('click',function(){
        model.style.display = 'block';
        let h1 = item.parentElement.querySelector('h1').innerText;
        childH1.innerText = h1;
        subject.value = h1;
    })
})
close.addEventListener('click',function(){
    model.style.display = 'none';
})

// let deleteBtn = document.querySelectorAll('.delete');
// let confirm_model = document.querySelectorAll(".confirm_model")
// deleteBtn.addEventListener('click',function(){
//     confirm_model.style.display = 'block';
// })
