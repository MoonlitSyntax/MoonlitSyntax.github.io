//随机背景图片数组,图片可以换成图床链接，注意最后一条后面不要有逗号
var backimg = [
  "url(https://img.siren.blue/img/1.jpg)",
  "url(https://img.siren.blue/img/2.jpg)",
  "url(https://img.siren.blue/img/3.jpg)",
  "url(https://img.siren.blue/img/4.jpg)",
  "url(https://img.siren.blue/img/5.jpg)",
  "url(https://img.siren.blue/img/6.jpg)",
  "url(https://img.siren.blue/img/7.jpg)",
  "url(https://img.siren.blue/img/8.jpg)",
  "url(https://img.siren.blue/img/9.jpg)",
  "url(https://img.siren.blue/img/10.jpg)",
  "url(https://img.siren.blue/img/11.jpg)",
  "url(https://img.siren.blue/img/12.jpg)",
  "url(https://img.siren.blue/img/13.jpg)",
  "url(https://img.siren.blue/img/14.jpg)",
  "url(https://img.siren.blue/img/17.jpg)",
  "url(https://img.siren.blue/img/15.jpg)",
  "url(https://img.siren.blue/img/16.jpg)",
  "url(https://img.siren.blue/img/18.jpg)",
  "url(https://img.siren.blue/img/20.jpg)",
  "url(https://img.siren.blue/img/19.jpg)",
  "url(https://img.siren.blue/img/21.png)",
  "url(https://img.siren.blue/img/22.jpg)",
  "url(https://img.siren.blue/img/23.jpg)",
  "url(https://img.siren.blue/img/24.jpg)",
  "url(https://img.siren.blue/img/25.jpg)"
];

  //获取背景图片总数，生成随机数
  const webBg = document.getElementById("web_bg");
  if (webBg) {
    const bgIndex = Math.floor(Math.random() * backimg.length);
    webBg.style.backgroundImage = backimg[bgIndex];
  }
