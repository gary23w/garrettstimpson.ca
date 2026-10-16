const walkthrough=document.getElementById('garrett-walkthrough');
for(const chapter of document.querySelectorAll('[data-guide-time]'))chapter.addEventListener('click',()=>{
  if(!walkthrough)return;
  // A small offset lands inside the chapter after the encoded transition.
  const seek=()=>{walkthrough.currentTime=Number(chapter.dataset.guideTime)+.75;walkthrough.play().catch(()=>{});};
  if(walkthrough.readyState>=1)seek();else{walkthrough.addEventListener('loadedmetadata',seek,{once:true});walkthrough.load();}
});
