//随机背景图片数组,图片可以换成图床链接，注意最后一条后面不要有逗号
var backimg =[
    "url(/img/1.jpg)",
    "url(/img/2.jpg)",
    "url(/img/3.jpg)",
    "url(/img/4.jpg)",
    "url(/img/5.jpg)",
    "url(/img/6.jpg)",
    "url(/img/7.jpg)",
    "url(/img/8.jpg)",
    "url(/img/9.jpg)",
    "url(/img/10.jpg)",
    "url(/img/11.jpg)",
    "url(/img/12.jpg)",
    "url(/img/13.jpg)",
    "url(/img/14.jpg)",
    "url(/img/17.jpg)",
    "url(/img/15.jpg)",
    "url(/img/16.jpg)",
    "url(/img/18.jpg)",
    "url(/img/20.jpg)",
    "url(/img/19.jpg)",
    "url(/img/21.png)",
    "url(/img/22.jpg)",
    "url(/img/23.jpg)",
    "url(/img/24.jpg)",
    "url(/img/25.jpg)"
  ];
  //获取背景图片总数，生成随机数
  var bgindex =Math.floor(Math.random() * backimg.length);
  //重设背景图片
  document.getElementById("web_bg").style.backgroundImage = backimg[bgindex];