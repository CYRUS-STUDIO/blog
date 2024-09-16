// 等待 DOM 加载完成
document.addEventListener('DOMContentLoaded', function () {
  const tocToggle = document.getElementById('toc-toggle');
  const tocContainer = document.getElementById('toc');
  const contentArea = document.querySelector('.post-content'); // 根据你的内容区域的类名调整

  // 生成目录函数
  function generateTOC() {
    const headings = contentArea.querySelectorAll('h1, h2, h3');
    console.log("Headings found:", headings); // 输出找到的标题元素
    if (headings.length === 0) {
      // 如果没有找到标题，隐藏浮动按钮
      tocToggle.style.display = 'none';
      return;
    }

    const tocList = document.createElement('ul');

    headings.forEach(function (heading) {
      if (!heading.id) {
        // 如果标题没有 id，生成一个
        heading.id = heading.textContent.trim().toLowerCase().replace(/\s+/g, '-').replace(/[^\w\-]/g, '');
      }

      const tocItem = document.createElement('li');
      tocItem.classList.add('toc-item', heading.tagName.toLowerCase());

      const tocLink = document.createElement('a');
      tocLink.href = `#${heading.id}`;
      tocLink.textContent = heading.textContent;

      tocItem.appendChild(tocLink);
      tocList.appendChild(tocItem);
    });

    tocContainer.appendChild(tocList);
  }

  // 页面加载时生成目录
  generateTOC();

  // 切换目录的显示与隐藏
  tocToggle.addEventListener('click', function () {
    console.log("TOC toggle clicked"); // 点击按钮时输出到控制台
    // 先检查当前是否是隐藏状态
        if (tocContainer.classList.contains("hidden")) {
            tocContainer.classList.remove("hidden");
            tocContainer.classList.add("visible");
        } else {
            tocContainer.classList.remove("visible");
            tocContainer.classList.add("hidden");
        }
  });

  // 点击目录项时平滑滚动到对应位置
  tocContainer.addEventListener('click', function (event) {
    if (event.target.tagName.toLowerCase() === 'a') {
      event.preventDefault();
      const targetId = event.target.getAttribute('href').substring(1);
      const targetHeading = document.getElementById(targetId);
      if (targetHeading) {
        window.scrollTo({
          top: targetHeading.offsetTop - 20, // 根据需要调整偏移量
          behavior: 'smooth'
        });
        // 点击后隐藏目录
        tocContainer.classList.remove("visible");
        tocContainer.classList.add("hidden");
      }
    }
  });
});
