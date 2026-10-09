import fs from 'node:fs/promises';
import path from 'node:path';
import {gzipSync} from 'node:zlib';

export async function packageGary(directory) {
  const files = JSON.parse(await fs.readFile(path.join(directory, 'files.json'), 'utf8'));
  const blocks = [];
  let total = 0;
  for (const file of files) {
    if (!/^[A-Za-z0-9_./-]+$/.test(file) || file.startsWith('/') || file.split('/').includes('..')) throw Error('Invalid Gary package path.');
    const content = Buffer.from((await fs.readFile(path.join(directory, file), 'utf8')).replace(/\r\n/g, '\n'), 'utf8');
    total += content.length;
    if (total > 32 * 1024 * 1024) throw Error('Gary source package exceeds 32 MiB.');
    const header = Buffer.alloc(512);
    const split = file.length > 100 ? file.lastIndexOf('/') : -1;
    const name = split < 0 ? file : file.slice(split + 1);
    const prefix = split < 0 ? '' : file.slice(0, split);
    if (Buffer.byteLength(name) > 100 || Buffer.byteLength(prefix) > 155) throw Error('Gary package path is too long.');
    header.write(name, 0, 100);
    header.write('0000644\0', 100, 8);
    header.write('0000000\0', 108, 8);
    header.write('0000000\0', 116, 8);
    header.write(content.length.toString(8).padStart(11, '0') + '\0', 124, 12);
    header.write('00000000000\0', 136, 12);
    header.fill(32, 148, 156);
    header.write('0', 156, 1);
    header.write('ustar\0', 257, 6);
    header.write('00', 263, 2);
    header.write(prefix, 345, 155);
    const checksum = header.reduce((sum, value) => sum + value, 0);
    header.write(checksum.toString(8).padStart(6, '0') + '\0 ', 148, 8);
    blocks.push(header, content, Buffer.alloc((512 - content.length % 512) % 512));
  }
  blocks.push(Buffer.alloc(1024));
  return gzipSync(Buffer.concat(blocks), {level:9});
}
