// assets/charts.js — XIGUASecurity 评测报告图表
(function () {
  var style = getComputedStyle(document.documentElement);
  var accent = style.getPropertyValue('--accent').trim();
  var accent2 = style.getPropertyValue('--accent2').trim();
  var ink = style.getPropertyValue('--ink').trim();
  var muted = style.getPropertyValue('--muted').trim();
  var rule = style.getPropertyValue('--rule').trim();
  var bg2 = style.getPropertyValue('--bg2').trim();
  var warn = style.getPropertyValue('--warn').trim();

  // --- Chart: 检出率对比 (bar) ---
  var el1 = document.getElementById('chart-detection');
  if (el1) {
    var chart1 = echarts.init(el1, null, { renderer: 'svg' });
    chart1.setOption({
      animation: false,
      grid: { left: 90, right: 40, top: 30, bottom: 30 },
      tooltip: {
        trigger: 'axis',
        axisPointer: { type: 'shadow' },
        appendToBody: true,
        formatter: function (params) {
          var p = params[0];
          return p.name + '：检出率 ' + p.value + '%';
        }
      },
      xAxis: {
        type: 'value',
        max: 100,
        axisLabel: { color: muted, formatter: '{value}%' },
        splitLine: { lineStyle: { color: rule } }
      },
      yAxis: {
        type: 'category',
        data: ['Avast（国际商业参考）', 'PYAS（自制杀软）', '火绒（商业国产）'],
        axisLabel: { color: ink, fontSize: 13 },
        axisLine: { lineStyle: { color: rule } }
      },
      series: [{
        type: 'bar',
        data: [
          { value: 93.4, itemStyle: { color: muted } },
          { value: 81.3, itemStyle: { color: accent } },
          { value: 39.0, itemStyle: { color: warn } }
        ],
        barWidth: 28,
        label: {
          show: true,
          position: 'right',
          color: ink,
          formatter: '{c}%',
          fontWeight: 700
        },
        itemStyle: { borderRadius: [0, 4, 4, 0] }
      }]
    });
    window.addEventListener('resize', function () { chart1.resize(); });
  }

  // --- Chart: 功能覆盖统计 (bar) ---
  var el2 = document.getElementById('chart-coverage');
  if (el2) {
    var chart2 = echarts.init(el2, null, { renderer: 'svg' });
    chart2.setOption({
      animation: false,
      grid: { left: 60, right: 50, top: 30, bottom: 30 },
      tooltip: {
        trigger: 'axis',
        axisPointer: { type: 'shadow' },
        appendToBody: true,
        formatter: function (params) {
          var p = params[0];
          return p.name + '：完整实现 ' + p.value + ' / 18 项核心能力';
        }
      },
      xAxis: {
        type: 'value',
        max: 18,
        axisLabel: { color: muted },
        splitLine: { lineStyle: { color: rule } }
      },
      yAxis: {
        type: 'category',
        data: ['XIGUASecurity 10x', 'HydraDragon', 'PYAS 3.6', 'Xdows 4.1'],
        axisLabel: { color: ink, fontSize: 13 },
        axisLine: { lineStyle: { color: rule } }
      },
      series: [{
        type: 'bar',
        data: [
          { value: 18, itemStyle: { color: accent } },
          { value: 12, itemStyle: { color: accent2 } },
          { value: 9, itemStyle: { color: accent2 + 'cc' } },
          { value: 4, itemStyle: { color: muted } }
        ],
        barWidth: 30,
        label: {
          show: true,
          position: 'right',
          color: ink,
          formatter: '{c}/18',
          fontWeight: 700
        },
        itemStyle: { borderRadius: [0, 4, 4, 0] }
      }]
    });
    window.addEventListener('resize', function () { chart2.resize(); });
  }
})();
