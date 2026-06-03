(() => {
  const locales = {
    en: {
      "settings.title": "🔐 Encryption Settings",
      "settings.passwordPlaceholder": "Encryption password",
      "settings.warningText": "⚠️ Use a strong password and remember it. It is impossible to recover access to messages without it.",
      "settings.autoSendLabel": "Automatically send messages",
      "settings.autoSendLabelNote": "Automatically send messages after encryption.",
      "settings.autoDecryptLabel": "Automatically decrypt messages",
      "settings.autoDecryptLabelNote": "Automatically decrypt messages when received. Works only for new messages and when a password is available.",
      "buttons.hide": "❌ Hide",
      "buttons.decrypt": "🔓 Decrypt",
      "buttons.settings": "⚙️ Settings",
      "buttons.tooltip": "Encrypt message",
      "toast.settingsSaved": "✅ Settings saved",
      "toast.noPassword": "⚠️ Please set a password in settings first (Right-click the button)",
      "toast.noText": "⚠️ No text to encrypt",
      "toast.messageSent": "✅ Message sent",
      "toast.sendFailed": "❌ Failed to send message",
      "toast.textEncrypted": "✅ Text encrypted",
      "errors.decrypt": "❌ Error: ",
      "errors.encrypt": "❌ Encryption error: ",
      "errors.notEncrypted": "Not an encrypted message"
    },
    ru: {
      "settings.title": "🔐 Настройки шифрования",
      "settings.passwordPlaceholder": "Пароль для шифрования",
      "settings.warningText": "⚠️ Используйте сложный пароль и запомните его. Восстановить доступ к сообщениям без него невозможно.",
      "settings.autoSendLabel": "Автоматически отправлять сообщения",
      "settings.autoSendLabelNote": "Автоматически отправлять сообщения после шифрования.",
      "settings.autoDecryptLabel": "Автоматически расшифровывать сообщения",
      "settings.autoDecryptLabelNote": "Автоматически расшифровывать сообщения при получении. Работает только для новых сообщений и при наличии пароля.",
      "buttons.hide": "❌ Скрыть",
      "buttons.decrypt": "🔓 Расшифровать",
      "buttons.settings": "⚙️ Настройки",
      "buttons.tooltip": "Шифрование сообщения",
      "toast.settingsSaved": "✅ Настройки сохранены",
      "toast.noPassword": "⚠️ Сначала установите пароль в настройках (ПКМ по кнопке)",
      "toast.noText": "⚠️ Нет текста для шифрования",
      "toast.messageSent": "✅ Сообщение отправлено",
      "toast.sendFailed": "❌ Не удалось отправить сообщение",
      "toast.textEncrypted": "✅ Текст зашифрован",
      "errors.decrypt": "❌ Ошибка: ",
      "errors.encrypt": "❌ Ошибка шифрования: ",
      "errors.notEncrypted": "Не зашифрованное сообщение"
    }
  };

  const t = (key) => locales[shelter.flux.stores?.LocaleStore?.locale]?.[key] ?? locales.en[key] ?? key;

  const createIcon = (path, size = 24) => `
    <svg viewBox="0 0 24 24" width="${size}" height="${size}" 
        fill="none" stroke="currentColor" stroke-width="2" 
        stroke-linecap="round" stroke-linejoin="round">
      ${path}
    </svg>`;

  const ICONS = {
    lock: createIcon(`
      <circle cx="12" cy="16" r="1"/>
      <rect x="3" y="10" width="18" height="12" rx="2"/>
      <path d="M7 10V7a5 5 0 0 1 10 0v3"/>
    `),
    eye: createIcon(`
      <path d="M2.062 12.348a1 1 0 0 1 0-.696 10.75 10.75 0 0 1 19.876 0 1 1 0 0 1 0 .696 10.75 10.75 0 0 1-19.876 0"/>
      <circle cx="12" cy="12" r="3"/>
    `),
    eyeOff: createIcon(`
      <path d="M10.733 5.076a10.744 10.744 0 0 1 11.205 6.575 1 1 0 0 1 0 .696 10.747 10.747 0 0 1-1.444 2.49"/>
      <path d="M14.084 14.158a3 3 0 0 1-4.242-4.242"/>
      <path d="M17.479 17.499a10.75 10.75 0 0 1-15.417-5.151 1 1 0 0 1 0-.696 10.75 10.75 0 0 1 4.446-5.143"/>
      <path d="m2 2 20 20"/>
    `)
  };

  return {
    onLoad() {
      this.decryptedCache = new Map();

      const CONFIG = {
        PREFIX: 'ENC:v1$',
        ITERATIONS: 600_000,
        SALT_LEN: 16,
        IV_LEN: 12
      };

      const base64url = {
        encode: (bytes) => {
          let bin = '';
          for (const b of bytes) bin += String.fromCharCode(b);
          return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
        },
        decode: (str) => {
          const pad = (4 - str.length % 4) % 4;
          return Uint8Array.from(atob(str.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat(pad)), c => c.charCodeAt(0));
        }
      };

      class DiscordE2EE {
        constructor(password) {
          this.password = password;
        }
        static isEncrypted(message) {
          return typeof message === 'string' && message.startsWith(CONFIG.PREFIX);
        }

        async _deriveKey(salt) {
          const keyMat = await crypto.subtle.importKey('raw', new TextEncoder().encode(this.password), 'PBKDF2', false, ['deriveKey']);
          return crypto.subtle.deriveKey({
              name: 'PBKDF2',
              salt,
              iterations: CONFIG.ITERATIONS,
              hash: 'SHA-256'
            },
            keyMat, {
              name: 'AES-GCM',
              length: 256
            }, false, ['encrypt', 'decrypt']
          );
        }

        async encrypt(plaintext) {
          const salt = crypto.getRandomValues(new Uint8Array(CONFIG.SALT_LEN));
          const iv = crypto.getRandomValues(new Uint8Array(CONFIG.IV_LEN));
          const ciphertext = await crypto.subtle.encrypt({
            name: 'AES-GCM',
            iv
          }, await this._deriveKey(salt), new TextEncoder().encode(plaintext));

          const combined = new Uint8Array(CONFIG.SALT_LEN + CONFIG.IV_LEN + ciphertext.byteLength);
          combined.set(salt, 0);
          combined.set(iv, CONFIG.SALT_LEN);
          combined.set(new Uint8Array(ciphertext), CONFIG.SALT_LEN + CONFIG.IV_LEN);
          return CONFIG.PREFIX + base64url.encode(combined);
        }

        async decrypt(encoded) {
          if (!DiscordE2EE.isEncrypted(encoded)) throw new Error(t('errors.notEncrypted'));
          const data = base64url.decode(encoded.slice(CONFIG.PREFIX.length));
          const salt = data.slice(0, CONFIG.SALT_LEN);
          const iv = data.slice(CONFIG.SALT_LEN, CONFIG.SALT_LEN + CONFIG.IV_LEN);
          const ciphertext = data.slice(CONFIG.SALT_LEN + CONFIG.IV_LEN);
          return new TextDecoder().decode(await crypto.subtle.decrypt({
            name: 'AES-GCM',
            iv
          }, await this._deriveKey(salt), ciphertext));
        }
      }

      const sendCurrentMessage = () => {
        let fiber = shelter.util.getFiber(document.querySelector('[class*="slateContainer"]'));
        
        while (fiber) {
          if (fiber.stateNode?.submit) {
            fiber.stateNode.submit();
            return true;
          }
          fiber = fiber.return;
        }
        return false;
      };

      const getDraftText = () => {
        const channelId = shelter.flux.stores.SelectedChannelStore.getChannelId();
        return shelter.flux.stores.DraftStore.getDraft(channelId, 0);
      };

      const setDraftText = (text) => {
        const elem = document.querySelector('[class*="slateContainer"]');
        if (!elem) return;
        const editor = shelter.util.getFiber(elem).child?.pendingProps?.editor;
        if (!editor) return;
        
        editor.children = [{type: "line", children: [{ text: text || "" }]}];
        editor.onChange();
      };

      const createCryptoButtons = async (messageElement, message) => {
        if (messageElement.querySelector('.e2ee-crypto-actions')) return;

        const encryptedContent = message.content;
        const messageId = message.id;

        const actionsContainer = document.createElement('div');
        actionsContainer.className = 'e2ee-crypto-actions';
        actionsContainer.style.marginTop = '4px';
        actionsContainer.style.display = 'flex';
        actionsContainer.style.flexDirection = 'column';
        actionsContainer.style.gap = '4px';

        const buttonsRow = document.createElement('div');
        buttonsRow.style.display = 'flex';
        buttonsRow.style.flexDirection = 'row';
        buttonsRow.style.gap = '8px';
        buttonsRow.style.alignItems = 'flex-start';

        const resultText = shelter.ui.Text({});

        const resultBlock = document.createElement('div');
        resultBlock.style.display = 'none';
        resultBlock.style.flexDirection = 'column';
        resultBlock.style.gap = '4px';

        const toggleResultButton = shelter.ui.Button({
          children: t('buttons.hide'),
          color: shelter.ui.ButtonColors?.RED,
          size: shelter.ui.ButtonSizes?.MEDIUM,
          style: { width: "fit-content" },
          onClick: () => resultBlock.style.display = 'none'
        });

        const decryptButton = shelter.ui.Button({
          children: t('buttons.decrypt'),
          color: shelter.ui.ButtonColors?.PRIMARY,
          size: shelter.ui.ButtonSizes?.MEDIUM,
          style: { width: "fit-content" },
          onClick: async () => {
            const pwd = shelter.plugin.store.password;
            if (!pwd) return shelter.ui.showToast({ color: shelter.ui.ToastColors?.WARNING, title: t('toast.noPassword') });
            
            if (this.decryptedCache.has(messageId)) {
              resultText.textContent = this.decryptedCache.get(messageId);
              resultBlock.style.display = 'flex';
              return;
            }
            
            try {
              const decrypted = await new DiscordE2EE(pwd).decrypt(encryptedContent);
              this.decryptedCache.set(messageId, decrypted);
              resultText.textContent = decrypted;
              resultBlock.style.display = 'flex';
            } catch (error) {
              shelter.ui.showToast({ color: shelter.ui.ToastColors?.CRITICAL, title: t('errors.decrypt') + (error.message || error.name || "Unknown error") });
            }
          }
        });

        const settingsButton = shelter.ui.Button({
          children: t('buttons.settings'),
          color: shelter.ui.ButtonColors?.SECONDARY,
          size: shelter.ui.ButtonSizes?.MEDIUM,
          style: { width: "fit-content" },
          onClick: () => shelter.plugin.showSettings()
        });

        buttonsRow.append(decryptButton, settingsButton);
        resultBlock.append(resultText, toggleResultButton);
        actionsContainer.append(buttonsRow, resultBlock);

        const accessories = messageElement.querySelector('[id*="message-accessories"]');
        if (accessories) {
          accessories.insertBefore(actionsContainer, accessories.firstChild);
        } else {
          const liParts = messageElement.id.split('-');
          const msgId = liParts[liParts.length - 1];
          const contentElement = messageElement.querySelector(`#message-content-${msgId}`);
          if (contentElement) contentElement.parentNode.insertBefore(actionsContainer, contentElement.nextSibling);
        }

        if ((shelter.plugin.store.autoDecrypt ?? true) && shelter.plugin.store.password) {
          if (this.decryptedCache.has(messageId)) {
            resultText.textContent = this.decryptedCache.get(messageId);
            resultBlock.style.display = 'flex';
          } else {
            try {
              const decrypted = await new DiscordE2EE(shelter.plugin.store.password).decrypt(encryptedContent);
              this.decryptedCache.set(messageId, decrypted);
              resultText.textContent = decrypted;
              resultBlock.style.display = 'flex';
            } catch {}
          }
        }
      };

      this.messageObserver = shelter.observeDom("li[id^='chat-messages-']", (li) => {
        ((li) => {
          const liParts = li.id.split('-');
          const messageId = liParts[liParts.length - 1];

          const contentEl = li.querySelector(`#message-content-${messageId}`);
          if (!contentEl) return;

          const fiber = shelter.util.getFiber(contentEl);
          if (!fiber) return;

          const message = fiber.return?.memoizedProps?.message;
          if (!message) return;

          const text = message.content || message.text || (typeof message.get === 'function' && message.get('content'));

          if (text && DiscordE2EE.isEncrypted(text) && !li._e2eeProcessed) {
            li._e2eeProcessed = true;
            createCryptoButtons(li, message);
          }
        })(li);
      });

      this.btnObserver = shelter.observeDom('[class*="channelTextArea"] [class*="buttons"]', (node) => {
        if (document.getElementById("e2ee-btn")) return;

        const referenceContainer = node.querySelector('[class*="buttonContainer"]');
        const innerButton = referenceContainer?.firstChild;
        if (!innerButton) return;

        const buttonContainer = document.createElement("div");
        buttonContainer.id = "e2ee-btn";
        buttonContainer.className = referenceContainer.className;

        const button = document.createElement("div");
        button.className = innerButton.className;
        button.setAttribute("role", "button");
        button.setAttribute("tabindex", "0");
        shelter.ui.tooltip(button, () => t('buttons.tooltip'));

        const wrapper = document.createElement("div");
        const referenceWrapper = innerButton.querySelector('[class*="buttonWrapper"]');
        wrapper.className = referenceWrapper ? referenceWrapper.className : '';
        wrapper.style.display = 'flex';
        wrapper.style.alignItems = 'center';
        wrapper.style.justifyContent = 'center';
        wrapper.innerHTML = ICONS.lock;

        button.append(wrapper);
        buttonContainer.append(button);
        node.insertBefore(buttonContainer, node.firstChild);

        button.onclick = async () => {
          const pwd = shelter.plugin.store.password;
          if (!pwd) return shelter.ui.showToast({ color: shelter.ui.ToastColors?.WARNING, title: t('toast.noPassword') });
          
          const text = getDraftText();
          if (!text || !text.trim()) return shelter.ui.showToast({ color: shelter.ui.ToastColors?.WARNING, title: t('toast.noText') });
          
          try {
            const encrypted = await new DiscordE2EE(pwd).encrypt(text);
            setDraftText(encrypted);
            
            if (shelter.plugin.store.autoSend ?? true) {
              if (sendCurrentMessage()) {
                shelter.ui.showToast({ color: shelter.ui.ToastColors?.SUCCESS, title: t('toast.messageSent') });
              } else {
                shelter.ui.showToast({ color: shelter.ui.ToastColors?.CRITICAL, title: t('toast.sendFailed') });
              }
            } else {
              shelter.ui.showToast({ color: shelter.ui.ToastColors?.SUCCESS, title: t('toast.textEncrypted') });
            }
          } catch (error) {
            shelter.ui.showToast({ color: shelter.ui.ToastColors?.CRITICAL, title: t('errors.encrypt') + (error.message || error.name || "Unknown error") });
          }
        };
        
        button.oncontextmenu = (event) => {
          event.preventDefault();
          shelter.plugin.showSettings();
        };
      });
    },

    onUnload() {
      this.messageObserver?.();
      this.btnObserver?.();

      document.querySelectorAll('.e2ee-crypto-actions').forEach(element => element.remove());
      document.getElementById("e2ee-btn")?.remove();
    },

    settings() {
      const { createSignal, createEffect, onCleanup } = shelter.solid;
      const { render } = shelter.solidWeb;
      
      const [password, setPassword] = createSignal(shelter.plugin.store.password || "");
      const [showPassword, setShowPassword] = createSignal(false);
      const [autoSend, setAutoSend] = createSignal(shelter.plugin.store.autoSend ?? true);
      const [autoDecrypt, setAutoDecrypt] = createSignal(shelter.plugin.store.autoDecrypt ?? true);

      const container = document.createElement('div');

      render(() => {
        const passwordBox = shelter.ui.TextBox({
          placeholder: t('settings.passwordPlaceholder'),
          value: password(),
          onInput: (val) => setPassword(val),
          type: "password",
          style: { "margin-right": "8px" }
        });

        createEffect(() => passwordBox.type = showPassword() ? "text" : "password");

        const renderIcon = (svgString) => {
          const wrapper = document.createElement('div');
          wrapper.style.display = 'flex';
          wrapper.style.alignItems = 'center';
          wrapper.style.justifyContent = 'center';
          wrapper.innerHTML = svgString;
          return wrapper;
        };

        const toggleBtn = shelter.ui.Button({
          children: () => renderIcon(showPassword() ? ICONS.eyeOff : ICONS.eye),
          color: shelter.ui.ButtonColors?.SECONDARY,
          size: shelter.ui.ButtonSizes?.LARGE,
          style: { width: "44px", "min-width": "44px" },
          onClick: () => setShowPassword(prev => !prev)
        });

        const passwordContainer = document.createElement('div');
        passwordContainer.style.display = 'flex';
        passwordContainer.style.alignItems = 'center';
        passwordContainer.style.marginBottom = '16px';
        passwordContainer.append(passwordBox, toggleBtn);

        const warningText = shelter.ui.Text({
          children: t('settings.warningText'),
          style: { display: "block", "margin-bottom": "16px" }
        });

        const divider = shelter.ui.Divider({ mt: true, mb: true });

        const autoSendSwitch = shelter.ui.SwitchItem({
          get value() { return autoSend(); },
          onChange: (val) => setAutoSend(val),
          children: t('settings.autoSendLabel'),
          note: t('settings.autoSendLabelNote'),
          hideBorder: true
        });

        const autoDecryptSwitch = shelter.ui.SwitchItem({
          get value() { return autoDecrypt(); },
          onChange: (val) => setAutoDecrypt(val),
          children: t('settings.autoDecryptLabel'),
          note: t('settings.autoDecryptLabelNote'),
          hideBorder: true
        });

        return [passwordContainer, warningText, divider, autoSendSwitch, autoDecryptSwitch];
      }, container);

      onCleanup(() => {
        shelter.plugin.store.password = password();
        shelter.plugin.store.autoSend = autoSend();
        shelter.plugin.store.autoDecrypt = autoDecrypt();
        shelter.ui.showToast({ color: shelter.ui.ToastColors?.SUCCESS, title: t('toast.settingsSaved') });
      });

      return container;
    }
  };
})()
