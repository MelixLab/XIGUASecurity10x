/**
 * 生成宣传片背景音乐 (WAV)
 * 程序化合成一段明亮、简洁、有节奏感的轻快配乐
 * 输出: public/bgm.wav (60秒, 44.1kHz, 16bit)
 */
const fs = require("fs");
const path = require("path");

const SAMPLE_RATE = 44100;
const DURATION = 60; // 秒
const NUM_SAMPLES = SAMPLE_RATE * DURATION;

// 输出目录
const outDir = path.join(__dirname, "public");
if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });

// 基础音高序列 (A小调，简洁欢快)
// 频率 = 440 * 2^((midi-69)/12)
const midiToFreq = (m) => 440 * Math.pow(2, (m - 69) / 12);

// 和弦进行: C - G - Am - F (明亮简洁)
const CHORDS = [
  [60, 64, 67], // C
  [55, 59, 62], // G
  [57, 60, 64], // Am
  [53, 57, 60], // F
];

// 主旋律 (MIDI 音符，-1 为休止)
const MELODY = [
  67, 69, 72, 74, 72, 69, 67, 72,
  74, 76, 79, 76, 74, 72, 74, 69,
  67, 69, 72, 74, 76, 79, 81, 84,
  79, 76, 74, 72, 74, 76, 79, -1,
];

const samples = new Float32Array(NUM_SAMPLES);

function addTone(start, dur, freq, amp, type = "sine") {
  const startIdx = Math.floor(start * SAMPLE_RATE);
  const num = Math.floor(dur * SAMPLE_RATE);
  for (let i = 0; i < num; i++) {
    const idx = startIdx + i;
    if (idx >= NUM_SAMPLES) break;
    const t = i / SAMPLE_RATE;
    // 包络: 快速起音，缓慢衰减 (钢琴风格)
    const env = Math.min(1, t / 0.01) * Math.pow(1 - t / dur, 2);
    let v = 0;
    switch (type) {
      case "sine":
        v = Math.sin(2 * Math.PI * freq * t);
        break;
      case "triangle":
        v = 2 / Math.PI * Math.asin(Math.sin(2 * Math.PI * freq * t));
        break;
      case "square":
        v = Math.sign(Math.sin(2 * Math.PI * freq * t)) * 0.5;
        break;
    }
    samples[idx] += v * env * amp;
  }
}

// 8秒一个循环 (和弦进度每2秒一个和弦，主旋律2秒/2音符)
const beatDur = 0.5; // 每个音符0.5秒
let globalIdx = 0;

for (let t = 0; t < DURATION; t += 0.5) {
  // 每个节拍
  const chordIndex = Math.floor(t / 2) % 4;
  const chord = CHORDS[chordIndex];
  const chordType = Math.floor(t / 0.5) % 4 === 0 ? "triangle" : "sine";

  // 琶音和弦 (每个半拍一个音符，构成轻快节奏)
  const noteIdx = Math.floor(t / 0.5) % 3;
  const chordFreq = midiToFreq(chord[noteIdx]);
  addTone(t, 0.45, chordFreq, 0.08, "sine");
  if (Math.floor(t / 0.5) % 4 === 0) {
    addTone(t, 0.4, midiToFreq(chord[0] - 12), 0.05, "sine"); // 低音
  }

  // 主旋律 (每1秒一个音符)
  const melodyIdx = Math.floor(t / 1);
  const melNote = MELODY[melodyIdx % MELODY.length];
  if (melNote !== -1) {
    addTone(t, 0.9, midiToFreq(melNote), 0.1, "sine");
  }
}

// 写入 WAV (16bit PCM)
function writeWav(data, filePath) {
  const buffer = Buffer.alloc(44 + data.length * 2);
  // RIFF header
  buffer.write("RIFF", 0);
  buffer.writeUInt32LE(36 + data.length * 2, 4);
  buffer.write("WAVE", 8);
  // fmt chunk
  buffer.write("fmt ", 12);
  buffer.writeUInt32LE(16, 16); // fmt chunk size
  buffer.writeUInt16LE(1, 20); // PCM
  buffer.writeUInt16LE(1, 22); // mono
  buffer.writeUInt32LE(SAMPLE_RATE, 24);
  buffer.writeUInt32LE(SAMPLE_RATE * 2, 28); // byte rate
  buffer.writeUInt16LE(2, 32); // block align
  buffer.writeUInt16LE(16, 34); // bits per sample
  // data chunk
  buffer.write("data", 36);
  buffer.writeUInt32LE(data.length * 2, 40);
  for (let i = 0; i < data.length; i++) {
    let v = Math.max(-1, Math.min(1, data[i]));
    buffer.writeInt16LE(Math.round(v * 32767), 44 + i * 2);
  }
  fs.writeFileSync(filePath, buffer);
}

writeWav(samples, path.join(outDir, "bgm.wav"));
console.log(`✓ 背景音乐已生成: public/bgm.wav (${DURATION}s)`);
