const form = document.getElementById('scanForm');
const urlInput = document.getElementById('url');
const results = document.getElementById('results');
const scanBtn = document.getElementById('scanBtn');


function renderJSON(obj){
return '<pre class="code">' + JSON.stringify(obj, null, 2) + '</pre>';
}


function addCard(title, content, type){
const div = document.createElement('div');
div.className = 'card';
div.innerHTML = `<h3>${title}</h3>${content}`;
results.prepend(div);
}


form.addEventListener('submit', async (e)=>{
e.preventDefault();
results.innerHTML = '';
const raw = urlInput.value.trim();
if(!raw) return;
scanBtn.disabled = true;
addCard('Scanning', `<p>Scanning <strong>${raw}</strong> — please wait...</p>`);


try{
const resp = await fetch('scan.php', {
method: 'POST',
headers: {'Content-Type':'application/json'},
body: JSON.stringify({url: raw})
});
const data = await resp.json();
results.innerHTML = '';


// Summary
const statusClass = data.risk && data.risk.level === 'high' ? 'bad' : 'good';
addCard('Summary', `<p>Risk: <span class='${statusClass}'>${data.risk.level.toUpperCase()}</span> — ${data.risk.reason}</p>`);


// Details
let detailHtml = '';
detailHtml += `<div class='kv'><strong>Final URL</strong><div>${data.final_url || '—'}</div></div>`;
detailHtml += `<div class='kv'><strong>HTTP Status</strong><div>${data.http_code || '—'}</div></div>`;
detailHtml += `<div class='kv'><strong>Content-Type</strong><div>${data.content_type || '—'}</div></div>`;
detailHtml += `<div class='kv'><strong>Redirects</strong><div>${data.redirect_count || 0}</div></div>`;
detailHtml += `<div class='kv'><strong>Server</strong><div>${data.server || '—'}</div></div>`;
if(data.suspicious && data.suspicious.length) {
detailHtml += `<div class='kv'><strong>Suspicious Flags</strong><div>${data.suspicious.join(', ')}</div></div>`;
}
addCard('Details', detailHtml);


if(data.sample) addCard('Content sample (truncated)', `<div class='code'>${data.sample}</div>`);


addCard('Raw JSON', renderJSON(data));
}catch(err){
results.innerHTML = '';
addCard('Error', `<p class='bad'>${err.message}</p>`);
} finally{
scanBtn.disabled = false;
}
});