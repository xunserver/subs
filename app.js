const state = {
  manifest: null,
  selectedId: null
}

const elements = {
  siteTitle: document.getElementById('siteTitle'),
  siteSubtitle: document.getElementById('siteSubtitle'),
  siteNotice: document.getElementById('siteNotice'),
  generatedAt: document.getElementById('generatedAt'),
  fileSelect: document.getElementById('fileSelect'),
  fileGrid: document.getElementById('fileGrid'),
  downloadForm: document.getElementById('downloadForm'),
  passphrase: document.getElementById('passphrase'),
  downloadButton: document.getElementById('downloadButton'),
  status: document.getElementById('status')
}

function setStatus(message, stateName = 'info') {
  elements.status.textContent = message
  elements.status.dataset.state = stateName
}

function formatBytes(bytes) {
  if (!Number.isFinite(bytes) || bytes <= 0) {
    return '0 B'
  }

  const units = ['B', 'KB', 'MB', 'GB']
  const exponent = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1)
  const value = bytes / (1024 ** exponent)

  return `${value.toFixed(value >= 10 || exponent === 0 ? 0 : 1)} ${units[exponent]}`
}

function formatDateTime(value) {
  try {
    return new Intl.DateTimeFormat('zh-CN', {
      dateStyle: 'medium',
      timeStyle: 'short'
    }).format(new Date(value))
  } catch {
    return value
  }
}

function getSelectedFile() {
  return state.manifest?.files.find((file) => file.id === state.selectedId) || null
}

function syncActiveCards() {
  const cards = elements.fileGrid.querySelectorAll('.file-card')

  for (const card of cards) {
    card.dataset.active = card.dataset.id === state.selectedId ? 'true' : 'false'
  }
}

function selectFile(fileId) {
  state.selectedId = fileId
  elements.fileSelect.value = fileId
  syncActiveCards()
}

function renderFiles(files) {
  elements.fileSelect.innerHTML = ''
  elements.fileGrid.innerHTML = ''

  for (const [index, file] of files.entries()) {
    const option = document.createElement('option')
    option.value = file.id
    option.textContent = `${file.downloadName} (${formatBytes(file.plainBytes)})`
    elements.fileSelect.append(option)

    const card = document.createElement('button')
    card.type = 'button'
    card.className = 'file-card'
    card.dataset.id = file.id
    card.dataset.active = index === 0 ? 'true' : 'false'
    card.innerHTML = `
      <h3>${file.downloadName}</h3>
      <p>${file.relativePath}</p>
      <span class="file-meta">${formatBytes(file.plainBytes)} plaintext</span>
    `
    card.addEventListener('click', () => selectFile(file.id))
    elements.fileGrid.append(card)
  }

  state.selectedId = files[0]?.id || null
  syncActiveCards()
}

function renderManifest(manifest) {
  state.manifest = manifest
  document.title = manifest.site.title
  elements.siteTitle.textContent = manifest.site.title
  elements.siteSubtitle.textContent = manifest.site.subtitle
  elements.siteNotice.textContent = manifest.site.notice
  elements.generatedAt.textContent = `Generated ${formatDateTime(manifest.generatedAt)}`
  renderFiles(manifest.files)
  setStatus(`已载入 ${manifest.files.length} 个加密配置。`, 'success')
}

function parsePayload(buffer) {
  const bytes = new Uint8Array(buffer)
  const magic = new TextDecoder().decode(bytes.subarray(0, 4))

  if (magic !== 'SCFG') {
    throw new Error('文件头不匹配，可能不是受支持的加密配置。')
  }

  const version = bytes[4]
  if (version !== 1) {
    throw new Error(`暂不支持的加密版本: ${version}`)
  }

  const saltLength = bytes[5]
  const ivLength = bytes[6]
  const saltOffset = 7
  const ivOffset = saltOffset + saltLength
  const cipherOffset = ivOffset + ivLength

  return {
    salt: bytes.slice(saltOffset, ivOffset),
    iv: bytes.slice(ivOffset, cipherOffset),
    ciphertext: bytes.slice(cipherOffset)
  }
}

async function deriveKey(passphrase, salt, manifest) {
  const encoder = new TextEncoder()
  const baseKey = await crypto.subtle.importKey(
    'raw',
    encoder.encode(passphrase),
    'PBKDF2',
    false,
    ['deriveKey']
  )

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations: manifest.kdf.iterations,
      hash: manifest.kdf.hash
    },
    baseKey,
    {
      name: 'AES-GCM',
      length: 256
    },
    false,
    ['decrypt']
  )
}

async function decryptFile(file, passphrase, manifest) {
  const response = await fetch(`./${file.asset}`, { cache: 'no-store' })

  if (!response.ok) {
    throw new Error(`无法读取加密文件: ${file.downloadName}`)
  }

  const payload = parsePayload(await response.arrayBuffer())
  const key = await deriveKey(passphrase, payload.salt, manifest)
  const plaintext = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: payload.iv
    },
    key,
    payload.ciphertext
  )

  return new TextDecoder().decode(plaintext)
}

function triggerDownload(text, file) {
  const blob = new Blob([text], { type: file.mimeType || 'text/plain;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')

  link.href = url
  link.download = file.downloadName
  link.click()

  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

async function handleSubmit(event) {
  event.preventDefault()

  if (!window.crypto?.subtle) {
    setStatus('当前浏览器不支持 Web Crypto，无法本地解密。', 'error')
    return
  }

  const file = getSelectedFile()
  const passphrase = elements.passphrase.value

  if (!file || !passphrase) {
    setStatus('请选择配置并输入密码。', 'error')
    return
  }

  elements.downloadButton.disabled = true
  setStatus(`正在解密 ${file.downloadName} ...`, 'info')

  try {
    const text = await decryptFile(file, passphrase, state.manifest)
    triggerDownload(text, file)
    setStatus(`${file.downloadName} 已在本地解密并开始下载。`, 'success')
  } catch {
    setStatus('解密失败。请检查密码是否正确，或确认公开仓库中的文件未被改动。', 'error')
  } finally {
    elements.downloadButton.disabled = false
  }
}

async function bootstrap() {
  setStatus('正在读取加密配置清单...', 'info')

  try {
    const response = await fetch('./manifest.json', { cache: 'no-store' })

    if (!response.ok) {
      throw new Error(`Manifest request failed: ${response.status}`)
    }

    const manifest = await response.json()

    if (!Array.isArray(manifest.files) || manifest.files.length === 0) {
      throw new Error('Manifest does not contain files.')
    }

    renderManifest(manifest)
  } catch {
    setStatus('无法加载公开配置清单，请确认 Pages 仓库已经成功发布。', 'error')
  }
}

elements.fileSelect.addEventListener('change', (event) => {
  selectFile(event.target.value)
})
elements.downloadForm.addEventListener('submit', handleSubmit)

bootstrap()
