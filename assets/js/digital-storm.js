// Self-hosted Three.js r170. Decorative, silent, and separate from navigation.
const root = document.getElementById('digital-storm');
const motionPreference = matchMedia('(prefers-reduced-motion: reduce)');
if (root) {
  let started = false;
  function launch() {
    if (started || motionPreference.matches || navigator.connection?.saveData) return;
    started = true;
    const load = () => startStorm().catch(error => {
      root.dataset.renderer = 'unavailable';
      console.warn('Digital storm could not start.', error);
    });
    // Let the article and navigation paint before loading the decorative scene.
    if (window.requestIdleCallback) window.requestIdleCallback(load, { timeout: 1500 });
    else setTimeout(load, 0);
  }
  motionPreference.addEventListener('change', launch);
  launch();
}

async function startStorm() {
  const THREE = await import('./vendor/three.module.min.js');
  const canvas = document.getElementById('storm-canvas');
  const mobile = matchMedia('(max-width: 700px)').matches;
  const renderer = new THREE.WebGLRenderer({ canvas, alpha: false, antialias: false, powerPreference: 'low-power' });
  renderer.setClearColor(0x010605, 1);
  renderer.setPixelRatio(Math.min(devicePixelRatio || 1, mobile ? 1 : 1.25));
  const scene = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(48, 1, .1, 140);
  camera.position.set(0, 1, 26);
  camera.lookAt(0, 0, -5);
  const rand = (a, b) => a + Math.random() * (b - a);
  const resources = [];
  const track = value => { resources.push(value); return value; };
  const initialAspect = innerWidth / innerHeight;
  const theme = getComputedStyle(document.documentElement);
  const themeColor = (name, fallback) => new THREE.Color(theme.getPropertyValue(name).trim() || fallback);
  const uniforms = {
    uTime: { value: 12 },
    uFlash: { value: 0 },
    uStrike: { value: new THREE.Vector2(.65, .65) },
    uResolution: { value: new THREE.Vector2(1, 1) },
    uWind: { value: 0 },
    uAspectScale: { value: 1 },
    uRainColor: { value: themeColor('--green', '#00ef72') },
    uLightningColor: { value: themeColor('--green-bright', '#09f77b') },
    uWhite: { value: themeColor('--heading', '#f3f7f1') },
  };
  let time = 12;
  let disposed = false;
  let contextLost = false;
  let frameId = 0;
  let previousFrame = 0;
  let lastStrike = -100;
  let nextStrike = time + rand(4, 7);
  let flash = 0;
  let slowFrames = 0;

  function shaderMaterial(vertexShader, fragmentShader, extra = {}) {
    fragmentShader = fragmentShader.replace(/}\s*$/, '#include <tonemapping_fragment>\n#include <colorspace_fragment>\n}');
    return track(new THREE.ShaderMaterial({ uniforms, vertexShader, fragmentShader, ...extra }));
  }
  const screenVertex = `varying vec2 vUv;
    void main() { vUv = uv; gl_Position = vec4(position.xy, 0., 1.); }`;

  // A slow moving cloud bank; lightning illuminates the cloud volume, not the page.
  const sky = new THREE.Mesh(track(new THREE.PlaneGeometry(2, 2)), shaderMaterial(screenVertex, `
    varying vec2 vUv;
    uniform float uTime, uFlash;
    uniform vec3 uRainColor, uLightningColor;
    uniform vec2 uStrike, uResolution;
    float hash(vec2 p) {
      vec3 p3 = fract(vec3(p.xyx) * .1031);
      p3 += dot(p3, p3.yzx + 33.33);
      return fract((p3.x + p3.y) * p3.z);
    }
    float noise(vec2 p) {
      vec2 i = floor(p), f = fract(p); f = f*f*(3.-2.*f);
      return mix(mix(hash(i), hash(i+vec2(1,0)), f.x), mix(hash(i+vec2(0,1)), hash(i+1.), f.x), f.y);
    }
    void main() {
      vec2 p = vUv * vec2(uResolution.x / uResolution.y * 3., 4.);
      p.x += uTime * .025;
      float cloud = noise(p) * .6 + noise(p * 2.1 + 7.) * .28 + noise(p * 4.3) * .12;
      float bank = smoothstep(.25, .95, vUv.y);
      float halo = exp(-length((vUv-uStrike)*vec2(1.1, 1.))*4.);
      vec3 col = uRainColor * (.001 + .018 * cloud * bank);
      col += uLightningColor * .3 * uFlash * (cloud * .65 + .35) * halo;
      col *= 1. - .5 * length(vUv-.5);
      gl_FragColor = vec4(col, 1.);
    }`, { depthTest: false, depthWrite: false }));
  sky.frustumCulled = false;
  sky.renderOrder = -10;
  scene.add(sky);

  // One atlas and one instanced draw call for every falling character.
  const atlas = document.createElement('canvas');
  atlas.width = 1024;
  atlas.height = 256;
  const ctx = atlas.getContext('2d');
  const glyphs = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{}[]<>/+=:;?!$#%&*@_|~^.-()01';
  ctx.font = 'bold 43px "Courier New", monospace';
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillStyle = '#fff';
  ctx.shadowColor = '#fff';
  ctx.shadowBlur = 4;
  for (let i = 0; i < 64; i++) ctx.fillText(glyphs[i % glyphs.length], (i % 16) * 64 + 32, Math.floor(i / 16) * 64 + 33);
  const atlasTexture = track(new THREE.CanvasTexture(atlas));
  atlasTexture.minFilter = THREE.LinearFilter;
  atlasTexture.generateMipmaps = false;
  uniforms.uAtlas = { value: atlasTexture };

  function instancedQuad(count, attributes) {
    const base = new THREE.PlaneGeometry(1, 1);
    const geometry = track(new THREE.InstancedBufferGeometry());
    geometry.index = base.index;
    geometry.attributes.position = base.attributes.position;
    geometry.attributes.uv = base.attributes.uv;
    geometry.instanceCount = count;
    for (const [name, [array, size]] of Object.entries(attributes)) {
      geometry.setAttribute(name, new THREE.InstancedBufferAttribute(new Float32Array(array), size));
    }
    base.dispose();
    return geometry;
  }
  const streams = mobile ? 115 : 280;
  const segments = mobile ? 18 : 24;
  const origins = [], motions = [], tokens = [];
  for (let i = 0; i < streams; i++) {
    const z = rand(-36, 14), speed = rand(2.4, 6.5), phase = rand(0, 42);
    const spread = Math.tan(24*Math.PI/180)*(26-z)*innerWidth/innerHeight;
    const x = rand(-spread*1.15, spread*1.15);
    const size = rand(.28, .52), length = rand(12, segments);
    for (let j = 0; j < segments; j++) {
      origins.push(x, 0, z);
      motions.push(speed, phase, size, length);
      tokens.push(j, rand(0, 999));
    }
  }
  const rainGeometry = instancedQuad(streams * segments, {
    aOrigin: [origins, 3], aMotion: [motions, 4], aToken: [tokens, 2],
  });
  const rain = new THREE.Mesh(rainGeometry, shaderMaterial(`
    attribute vec3 aOrigin;
    attribute vec4 aMotion;
    attribute vec2 aToken;
    uniform float uTime, uWind, uAspectScale;
    varying vec2 vUv;
    varying float vTail, vSeed, vDepth;
    void main() {
      float head = 24. - mod(uTime * aMotion.x + aMotion.y, 42.);
      float tail = aToken.x / aMotion.w;
      vec3 p = aOrigin;
      p.x *= uAspectScale;
      p.y = head + aToken.x * aMotion.z * 1.23;
      p.x += (head - 15.) * (.035 + uWind * .025);
      p.x += sin(uTime * .22 + aMotion.y) * .25;
      vec4 mv = modelViewMatrix * vec4(p, 1.);
      mv.xy += position.xy * aMotion.z;
      gl_Position = projectionMatrix * mv;
      vUv = uv; vTail = tail; vSeed = aToken.y;
      vDepth = clamp(1. - (-aOrigin.z + 6.) / 85., .16, 1.);
    }`, `
    uniform sampler2D uAtlas;
    uniform float uTime, uFlash;
    uniform vec3 uRainColor, uLightningColor, uWhite;
    varying vec2 vUv;
    varying float vTail, vSeed, vDepth;
    float hash(float n) { return fract(sin(n)*43758.5453); }
    void main() {
      if (vTail > 1.) discard;
      float character = floor(hash(vSeed + floor(uTime * (2. + hash(vSeed)*5.))) * 64.);
      vec2 cell = vec2(mod(character,16.), floor(character/16.));
      vec2 at = vec2((cell.x+vUv.x)/16., 1.-(cell.y+1.-vUv.y)/4.);
      float ink = texture2D(uAtlas, at).a;
      float head = 1. - smoothstep(0., .12, vTail);
      vec3 color = mix(uRainColor, uWhite, head);
      color = mix(color, uLightningColor, uFlash * .35);
      float alpha = ink * pow(1.-vTail, 1.45) * vDepth * (.68+head*.32);
      gl_FragColor = vec4(color, alpha);
    }`, { transparent: true, blending: THREE.AdditiveBlending, depthWrite: false }));
  rain.frustumCulled = false;
  scene.add(rain);

  // Fine droplets move faster than the glyph trails, giving the rain physical weight.
  const drops = mobile ? 450 : 1200;
  const dropOrigins = [], dropMotion = [];
  for (let i = 0; i < drops; i++) {
    const z = rand(-42, 15);
    const spread = Math.tan(24*Math.PI/180)*(26-z)*innerWidth/innerHeight;
    dropOrigins.push(rand(-spread*1.2, spread*1.2), 0, z);
    dropMotion.push(rand(9, 17), rand(0, 40), rand(.13, .65), rand(.1, .6));
  }
  const streaks = new THREE.Mesh(instancedQuad(drops, { aOrigin: [dropOrigins, 3], aMotion: [dropMotion, 4] }), shaderMaterial(`
    attribute vec3 aOrigin; attribute vec4 aMotion;
    uniform float uTime, uWind, uAspectScale;
    varying vec2 vUv; varying float vAlpha;
    void main() {
      vec3 p = aOrigin;
      p.x *= uAspectScale;
      p.y = 24. - mod(uTime*aMotion.x+aMotion.y, 40.);
      p.x += (p.y-15.) * (.035+uWind*.025);
      p.x += position.y * aMotion.z * .05;
      vec4 mv = modelViewMatrix * vec4(p,1.);
      mv.xy += position.xy * vec2(.014,aMotion.z);
      gl_Position = projectionMatrix * mv;
      vUv = uv;
      vAlpha = aMotion.w * clamp(1.-(-p.z+10.)/75.,.1,1.);
    }`, `
    varying vec2 vUv; varying float vAlpha; uniform float uFlash;
    uniform vec3 uRainColor, uLightningColor;
    void main() {
      float a = (1.-abs(vUv.x-.5)*2.) * pow(vUv.y,.6) * vAlpha;
      gl_FragColor = vec4(mix(uRainColor,uLightningColor,uFlash),a*.52);
    }`, { transparent: true, blending: THREE.AdditiveBlending, depthWrite: false }));
  streaks.frustumCulled = false;
  scene.add(streaks);

  // Translucent green arcs and a soft halo blend the lightning into the rain.
  const bolts = new THREE.Group();
  scene.add(bolts);
  const boltColor = uniforms.uLightningColor.value.clone().lerp(uniforms.uWhite.value, .2);
  const boltMaterial = track(new THREE.MeshBasicMaterial({ color: boltColor, transparent: true, depthWrite: false, blending: THREE.AdditiveBlending }));
  const glowMaterial = track(new THREE.MeshBasicMaterial({ color: uniforms.uLightningColor.value, transparent: true, depthWrite: false, blending: THREE.AdditiveBlending }));
  function boltPath(start, end, jitter, steps = 17) {
    const points = [start];
    for (let i = 1; i < steps; i++) {
      const p = start.clone().lerp(end, i / steps);
      p.x += rand(-jitter, jitter);
      p.z += rand(-.25, .25);
      points.push(p);
    }
    points.push(end);
    return points;
  }
  function addBolt(points, thickness) {
    const path = new THREE.CurvePath();
    for (let i = 1; i < points.length; i++) path.add(new THREE.LineCurve3(points[i-1], points[i]));
    for (const [radius, material] of [[thickness, boltMaterial], [thickness * 7, glowMaterial]]) {
      const geometry = new THREE.TubeGeometry(path, points.length * 2, radius, 4, false);
      bolts.add(new THREE.Mesh(geometry, material));
    }
  }
  function clearBolts() {
    for (const mesh of [...bolts.children]) { mesh.geometry.dispose(); bolts.remove(mesh); }
  }
  function strike() {
    if (contextLost || motionPreference.matches) return;
    clearBolts();
    const side = Math.random() > .5 ? 1 : -1;
    const halfWidth = Math.tan(24*Math.PI/180)*41*camera.aspect;
    const x = side * rand(halfWidth*.88, halfWidth*.96);
    const points = boltPath(new THREE.Vector3(x, 20, -15), new THREE.Vector3(x+rand(-1.6,1.6), -18, -15), .85, 24);
    addBolt(points, .065);
    for (const index of [5, 9, 14]) {
      const start = points[index];
      addBolt(boltPath(start, start.clone().add(new THREE.Vector3(-side*rand(2.5,5), -rand(3,7), 0)), .6, 8), .018);
    }
    lastStrike = time;
    nextStrike = time + rand(18, 34);
    uniforms.uStrike.value.set(.5 + side*.45, .75);
  }
  function draw() {
    uniforms.uTime.value = time;
    uniforms.uFlash.value = flash;
    uniforms.uWind.value = Math.sin(time*.17)*.7;
    renderer.render(scene,camera);
  }
  function frame(stamp) {
    frameId = 0;
    if (disposed || motionPreference.matches || contextLost || document.hidden) return;
    frameId = requestAnimationFrame(frame);
    // Target 60 fps without catch-up bursts after a hidden tab.
    if (stamp-previousFrame < 15.5) return;
    const elapsed = previousFrame ? stamp-previousFrame : 1000/60;
    const delta = Math.min(elapsed/1000,.1);
    previousFrame = stamp;
    time += delta;
    if (!motionPreference.matches && time >= nextStrike) strike();
    const age = time-lastStrike;
    const lightningFade = age < 3.2 ? Math.exp(-age*1.55) : 0;
    flash = lightningFade*.2;
    boltMaterial.opacity = lightningFade*.35;
    glowMaterial.opacity = lightningFade*.1;
    bolts.visible = age < 3.2;
    draw();
    // Reduce resolution on a busy device while keeping text at native resolution.
    slowFrames = elapsed > 42 ? slowFrames+1 : Math.max(0,slowFrames-1);
    if (slowFrames >= 30 && renderer.getPixelRatio() > .75) {
      renderer.setPixelRatio(Math.max(.75,renderer.getPixelRatio()-.25));
      slowFrames = 0;
    }
  }
  function restart() {
    cancelAnimationFrame(frameId);
    previousFrame=0;
    if (!disposed && !motionPreference.matches && !document.hidden && !contextLost) frameId=requestAnimationFrame(frame);
  }
  function resize() {
    renderer.setSize(innerWidth,innerHeight,false);
    uniforms.uResolution.value.set(innerWidth,innerHeight);
    camera.aspect=innerWidth/innerHeight;
    uniforms.uAspectScale.value=camera.aspect/initialAspect;
    camera.updateProjectionMatrix();
    if (!contextLost) draw();
  }
  const abort = new AbortController();
  const on = (element,event,handler,options={}) => element.addEventListener(event,handler,{...options,signal:abort.signal});
  on(window,'resize',resize,{passive:true});
  on(document,'visibilitychange',restart);
  on(motionPreference,'change',restart);
  on(canvas,'webglcontextlost',event=>{
    event.preventDefault(); contextLost=true; cancelAnimationFrame(frameId);
    root.dataset.renderer='unavailable';
  });
  on(canvas,'webglcontextrestored',()=>{ contextLost=false; root.dataset.renderer='webgl'; resize(); restart(); });
  on(window,'pagehide',event=>{
    cancelAnimationFrame(frameId);
    if(event.persisted) return;
    disposed=true; abort.abort(); clearBolts();
    for(const resource of resources) resource.dispose();
    renderer.dispose();
  });
  on(window,'pageshow',()=>{ if(!disposed) restart(); });
  root.dataset.renderer='webgl';
  resize(); restart();
}
