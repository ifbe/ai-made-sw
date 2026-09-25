(function (global) {
  'use strict';

  function parse(text) {
    const tokens = text.match(/"(?:[^"\\]|\\.)*"|\(|\)|[^\s()]+/g) || [];
    let pos = 0;
    function expr() {
      const t = tokens[pos++];
      if (t === '(') {
        const list = [];
        while (tokens[pos] !== ')') list.push(expr());
        pos++;
        return list;
      }
      if (t && t[0] === '"') return t.slice(1, -1).replace(/\\(.)/g, '$1');
      const n = Number(t);
      return isNaN(n) ? t : n;
    }
    return expr();
  }

  function find(node, tag) {
    for (const c of node) if (Array.isArray(c) && c[0] === tag) return c;
    return null;
  }

  function findAll(node, tag) {
    return node.filter(c => Array.isArray(c) && c[0] === tag);
  }

  function safeNum(v, fallback = 0) {
    return (typeof v === 'number' && isFinite(v)) ? v : fallback;
  }

  // 把解析后的节点还原成 KiCad 文件风格的文本
  // 列表第一个元素和 '(' 同行，后续子元素各占一行，缩进用一个 tab
  function stringifySexpr(node, indent) {
    indent = indent || '';
    if (Array.isArray(node)) {
      if (node.length === 0) return '()';
      let out = '(' + atomToString(node[0]);
      for (let i = 1; i < node.length; i++) {
        const child = node[i];
        if (Array.isArray(child)) {
          out += '\n' + indent + '\t' + stringifySexpr(child, indent + '\t');
        } else {
          out += ' ' + atomToString(child);
        }
      }
      out += '\n' + indent + ')';
      return out;
    }
    return atomToString(node);
  }

  function atomToString(v) {
    if (typeof v === 'string') {
      // 含空格或空字符串时加引号
      if (v === '' || /[\s()"]/.test(v)) {
        return '"' + v.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
      }
      return v;
    }
    return String(v);
  }

  global.KiPreview = global.KiPreview || {};
  global.KiPreview.Sexpr = { parse, find, findAll, safeNum, stringifySexpr };
})(window);