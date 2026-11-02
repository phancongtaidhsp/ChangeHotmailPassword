const axios = require('axios-https-proxy-fix');
const cheerio = require('cheerio');
const { toAxiosProxy } = require('./proxy');

const instance = axios.create({
  timeout: 15000,
})

const OTP_WAIT_TIMEOUT_MS = 30000;
const REQUEST_TIMEOUT_MS = 15000;

const requestTm = async (options) => {
  if (!options.signal) return instance.request(options);
  // axios-https-proxy-fix uses CancelToken rather than AbortSignal.
  const cancellation = axios.CancelToken.source();
  const abort = () => cancellation.cancel('Mail.tm request cancelled');
  options.signal.addEventListener('abort', abort, { once: true });
  if (options.signal.aborted) abort();
  try {
    return await instance.request({ ...options, cancelToken: cancellation.token });
  } finally {
    options.signal.removeEventListener('abort', abort);
  }
}

const delay = (ms) => {
  return new Promise(resolve => setTimeout(resolve, ms));
}

const getRemainingTimeout = (deadline) => {
  return Math.max(1, Math.min(REQUEST_TIMEOUT_MS, deadline - Date.now()));
}

const delayBeforeNextOtpAttempt = async (deadline, delayMs, signal) => {
  const remaining = deadline - Date.now();
  if (remaining <= 0 || signal?.aborted) return;

  await new Promise(resolve => {
    const timeoutId = setTimeout(finish, Math.min(delayMs, remaining));

    function finish() {
      clearTimeout(timeoutId);
      signal?.removeEventListener('abort', finish);
      resolve();
    }

    signal?.addEventListener('abort', finish, { once: true });
  });
}

const getLastSecurityCodeMailByFviainboxes = async (proxy, email, timeout, signal) => {
  let username = email.split("@")[0];
  let domain = email.split("@")[1];
  return new Promise((resolve) => {
    var options = {
      method: 'GET',
      url: `https://fviainboxes.com/messages?username=${username}&domain=${domain}`,
      headers: {
        'accept': 'application/ld+json',
        'Content-Type': 'application/ld+json',
        'Authorization': `Bearer af2b556e5e719052ca9193bace296b4fe9015bdc6c2c6ec28447d57c56187941`
      },
      timeout,
      signal,
    };
    if (proxy) {
      options.proxy = proxy;
    }
    instance.request(options)
      .then(function (response) {
        let id = null;
        if (response?.data?.result) {
          for (const message of response?.data?.result) {
            if (message?.subject?.toLowerCase().includes("code")
              && message?.from?.toLowerCase().includes("microsoft")) {
              id = message?.id;
              break;
            }
          }
        }
        resolve(id);
      }).catch((e) => {
        resolve(null);
      });
  })
}

const getCodeFviainboxes = async (proxy, email, id, timeout, signal) => {
  let username = email.split("@")[0];
  let domain = email.split("@")[1];
  return new Promise((resolve) => {
    var options = {
      method: 'GET',
      url: `https://fviainboxes.com/message?username=${username}&domain=${domain}&id=${id}`,
      headers: {
        'accept': 'application/ld+json',
        'Content-Type': 'application/ld+json',
        'Authorization': `Bearer af2b556e5e719052ca9193bace296b4fe9015bdc6c2c6ec28447d57c56187941`
      },
      timeout,
      signal,
    };
    if (proxy) {
      options.proxy = proxy;
    }
    instance.request(options)
      .then(function (response) {
        let code = null;
        let message = response?.data;
        if (message) {
          const match = message.match(/>\d{6}</);
          code = match ? match[0].replace(/>|</g, "") : null;
          if (!code) {
            const match1 = message.match(/: \d{6}/);
            code = match1 ? match1[0].replace(/: /g, "") : null;
          }
        }
        resolve(code);
      }).catch((e) => {
        resolve(null);
      });
  })
}

const getCodeFviainboxesByEmail = async (email, proxyString, signal) => {
  const proxy = toAxiosProxy(proxyString);
  const deadline = Date.now() + OTP_WAIT_TIMEOUT_MS;
  let id = null;

  while (Date.now() < deadline && !signal?.aborted) {
    id = await getLastSecurityCodeMailByFviainboxes(proxy, email, getRemainingTimeout(deadline), signal);
    if (id) {
      break;
    }
    await delayBeforeNextOtpAttempt(deadline, 3000, signal);
  }

  if (id) {
    while (Date.now() < deadline && !signal?.aborted) {
      let code = await getCodeFviainboxes(proxy, email, id, getRemainingTimeout(deadline), signal);
      if (code) {
        return code;
      }
      await delayBeforeNextOtpAttempt(deadline, 2000, signal);
    }
  }
  return null;
}

const tryGetCodeSmvMailByEmail = async (proxy, email, timeout, signal) => {
  return new Promise((resolve) => {
    var options = {
      method: 'GET',
      url: `https://api.smvmail.com/email?page=1&q=&email=${email}`,
      headers: {
        'accept': 'application/json, text/plain, */*'
      },
      timeout,
      signal,
    };
    if (proxy) {
      options.proxy = proxy;
    }
    instance.request(options)
      .then(function (response) {
        let messages = response?.data?.data?.docs;
        let code = null;
        if (messages && messages.length) {
          for (let message of messages) {
            if (code) {
              break;
            }
            if (message?.subject?.toLowerCase()?.includes("code")
              && message?.from?.toLowerCase()?.includes("microsoft")) {
              let messageContent = message.text;
              const match = messageContent.match(/>\d{6}</);
              code = match ? match[0].replace(/>|</g, "") : null;
              if (!code) {
                const match1 = messageContent.match(/: \d{6}/);
                code = match1 ? match1[0].replace(/: /g, "") : null;
              }
            }
          }
        }
        resolve(code);
      }).catch((e) => {
        resolve(null);
      });
  })
}

const getCodeSmvMailByEmail = async (email, proxyString, signal) => {
  const proxy = toAxiosProxy(proxyString);
  const deadline = Date.now() + OTP_WAIT_TIMEOUT_MS;

  while (Date.now() < deadline && !signal?.aborted) {
    let code = await tryGetCodeSmvMailByEmail(proxy, email, getRemainingTimeout(deadline), signal);
    if (code) {
      return code;
    }
    await delayBeforeNextOtpAttempt(deadline, 3000, signal);
  }
  return null;
}

const DEFAULT_TM_PASSWORD = 'Lumiong47@';

const reportTmError = (operation, error) => {
  // Do not log the Axios error/config: it contains the password or bearer token.
  const status = error.response?.status;
  console.error(`[Mail.tm] ${operation}: ${status ? `HTTP ${status}` : error.code || 'request failed'}`);
}

const createTmEmail = async (email, password = DEFAULT_TM_PASSWORD, requestOptions = {}) => {
  if (requestOptions.signal?.aborted) return null;
  let data = JSON.stringify({
    "address": email,
    "password": password
  });
  return new Promise((resolve) => {
    var options = {
      method: 'POST',
      url: `https://api.mail.tm/accounts`,
      headers: { 
        'accept': 'application/ld+json', 
        'Content-Type': 'application/ld+json'
      },
      data: data,
      timeout: requestOptions.timeout ?? REQUEST_TIMEOUT_MS,
      signal: requestOptions.signal,
      ...(requestOptions.proxy ? { proxy: requestOptions.proxy } : {}),
    };
    requestTm(options)
      .then(function (response) {
        if (response?.data?.id) {
          resolve(response.data.id);
        } else {
          resolve(null);
        }
      }).catch((e) => {
        if (!requestOptions.signal?.aborted) reportTmError('Không tạo được tài khoản', e);
        resolve(null);
      });
  })
}

const getTokenTmEmail = async (email, password = DEFAULT_TM_PASSWORD, requestOptions = {}) => {
  if (requestOptions.signal?.aborted) return null;
  let data = JSON.stringify({
    "address": email,
    "password": password
  });
  return new Promise((resolve) => {
    var options = {
      method: 'POST',
      url: `https://api.mail.tm/token`,
      headers: { 
        'accept': 'application/ld+json', 
        'Content-Type': 'application/ld+json'
      },
      data: data,
      timeout: requestOptions.timeout ?? REQUEST_TIMEOUT_MS,
      signal: requestOptions.signal,
      ...(requestOptions.proxy ? { proxy: requestOptions.proxy } : {}),
    };
    requestTm(options)
      .then(function (response) {
        if (response?.data?.token) {
          resolve(response.data.token);
        } else {
          resolve(null);
        }
      }).catch((e) => {
        if (!requestOptions.signal?.aborted) {
          reportTmError('Không lấy được token (kiểm tra địa chỉ và mật khẩu hộp thư)', e);
        }
        resolve(null);
      });
  })
}

const isMicrosoftTmMessage = (message) => {
  const address = message.from?.address || '';
  const domain = address.slice(address.lastIndexOf('@') + 1).toLowerCase();
  return domain === 'microsoft.com' || domain.endsWith('.microsoft.com')
    || /microsoft/i.test(message.subject || '');
}

const extractTmCode = (message) => {
  const htmlParts = Array.isArray(message.html) ? message.html : [message.html];
  const htmlText = htmlParts.filter(part => typeof part === 'string').map(part => {
    const $ = cheerio.load(part);
    $('script, style').remove();
    $('br').replaceWith('\n');
    $('p, div, td, tr').append('\n');
    return $.root().text();
  });
  const contents = [message.text, ...htmlText, message.subject, message.intro];
  const codeSubject = /\bcode\b|mã|xác minh/iu.test(message.subject || '');

  for (const content of contents) {
    if (typeof content !== 'string') continue;
    const labeledCode = content.match(/(?:\bcode\b|mã(?:\s+(?:bảo mật|xác minh|dùng một lần))?)[^\d]{0,80}\b(\d{6,7})\b/iu);
    if (labeledCode) return labeledCode[1];
    // Only accept an unlabeled number when the subject actually describes a code.
    const standaloneCode = codeSubject && content.match(/\b(\d{6,7})\b/u);
    if (standaloneCode) return standaloneCode[1];
  }
  return null;
}

const findCodeTmEmail = async (token, signal, { proxy, deadline = Infinity } = {}) => {
  if (!token || signal?.aborted) return null;
  const headers = {
    accept: 'application/ld+json',
    Authorization: `Bearer ${token}`,
  };

  try {
    let page = 1;
    let hasNextPage;
    do {
      if (Date.now() >= deadline || signal?.aborted) return null;
      const response = await requestTm({
        method: 'GET', url: 'https://api.mail.tm/messages',
        headers, params: { page }, signal,
        timeout: getRemainingTimeout(deadline),
        ...(proxy ? { proxy } : {}),
      });
      const messages = response.data?.['hydra:member'];
      if (!Array.isArray(messages)) return null;
      const candidates = messages.filter(message => !message.isDeleted && isMicrosoftTmMessage(message))
        .sort((a, b) => (Date.parse(b.createdAt) || 0) - (Date.parse(a.createdAt) || 0));

      for (const message of candidates) {
        if (Date.now() >= deadline || signal?.aborted) return null;
        // /messages only contains a truncated intro. The code may be in text/html.
        let detail = {};
        if (message.id) {
          try {
            const response = await requestTm({
              method: 'GET', url: `https://api.mail.tm/messages/${encodeURIComponent(message.id)}`,
              headers, signal,
              timeout: getRemainingTimeout(deadline),
              ...(proxy ? { proxy } : {}),
            });
            detail = response.data || {};
          } catch (error) {
            if (error.response?.status !== 404) throw error;
            continue; // The message may have been removed after listing it.
          }
        }
        const code = extractTmCode({ ...message, ...detail });
        if (code) return code;
      }
      hasNextPage = Boolean(response.data?.['hydra:view']?.['hydra:next']);
      page += 1;
    } while (hasNextPage && !signal?.aborted);
  } catch (error) {
    if (!signal?.aborted) reportTmError('Không đọc được thư', error);
  }
  return null;
}

const getCodeTmMailByEmail = async (email, proxyString, signal, password = DEFAULT_TM_PASSWORD) => {
  if (!email || signal?.aborted) return null;
  const proxy = toAxiosProxy(proxyString);
  const deadline = Date.now() + OTP_WAIT_TIMEOUT_MS;
  let token = null;

  while (Date.now() < deadline && !signal?.aborted) {
    if (!token) {
      token = await getTokenTmEmail(email, password, {
        proxy, signal, timeout: getRemainingTimeout(deadline),
      });
    }
    if (token && Date.now() < deadline && !signal?.aborted) {
      const code = await findCodeTmEmail(token, signal, { proxy, deadline });
      if (code && !signal?.aborted && Date.now() < deadline) return code;
    }
    await delayBeforeNextOtpAttempt(deadline, 3000, signal);
  }
  return null;
}

if (require.main === module) {
  (async () => {
    const email = process.argv[2] || process.env.MAIL_TM_EMAIL || 'nitschkeyaovb55678@sharebot.net';
    const proxy = process.argv[3] || process.env.MAIL_TM_PROXY;
    const code = await getCodeTmMailByEmail(email, proxy, undefined, process.env.MAIL_TM_PASSWORD);
    console.log(code || '[Mail.tm] Chưa tìm thấy mã Microsoft trong hộp thư.');
    if (!code) process.exitCode = 1;
  })().catch(() => {
    console.error('[Mail.tm] Không thể hoàn tất kiểm tra hộp thư.');
    process.exitCode = 1;
  });
}

module.exports = {
  delay,
  getCodeFviainboxesByEmail,
  getCodeSmvMailByEmail,
  getCodeTmMailByEmail,
  createTmEmail,
  getTokenTmEmail,
  findCodeTmEmail,
};
