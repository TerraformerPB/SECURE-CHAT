import sharp from 'sharp';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const clientDir = join(__dirname, '..', 'client');
const svg = join(clientDir, 'icon.svg');

sharp(svg).resize(192, 192).png().toFile(join(clientDir, 'icon-192.png'))
  .then(() => sharp(svg).resize(512, 512).png().toFile(join(clientDir, 'icon-512.png')))
  .then(() => console.log('Icons created'))
  .catch(e => console.error(e));
