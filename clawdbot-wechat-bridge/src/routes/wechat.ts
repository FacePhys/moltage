import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { getConfig } from '../config.js';
import { validateSignature } from '../utils/signature.js';
import { parseWeChatXml, buildTextReply } from '../utils/xml-parser.js';
import { getVMBinding, setVMBinding, deleteVMBinding, updateVMBindingStatus, VMBinding } from '../services/redis.js';
import { getOrchestratorClient, VMInfo } from '../services/orchestrator-client.js';
import { forwardToClawdbot } from '../services/clawdbot-forwarder.js';
import {
    decryptMessage,
    encryptMessage,
    validateMsgSignature,
    extractEncryptedContent,
    buildEncryptedReply,
    generateMsgSignature,
} from '../utils/crypto.js';

// User commands
const STATUS_REGEX = /^status$/i;
const RESTART_REGEX = /^restart$/i;
const STOP_REGEX = /^stop$/i;
const DESTROY_REGEX = /^destroy$/i;
const HELP_REGEX = /^help$/i;
const PASSWD_REGEX = /^passwd\s+(\S+)$/i;

interface WeChatQueryParams {
    signature: string;
    timestamp: string;
    nonce: string;
    echostr?: string;
    encrypt_type?: string;
    msg_signature?: string;
    openid?: string;
}

export async function wechatRoutes(fastify: FastifyInstance): Promise<void> {
    const config = getConfig();
    const orchestrator = getOrchestratorClient();

    /**
     * GET /wechat - WeChat server validation endpoint
     */
    fastify.get<{ Querystring: WeChatQueryParams }>(
        '/wechat',
        async (request, reply) => {
            const { signature, timestamp, nonce, echostr } = request.query;

            if (!signature || !timestamp || !nonce) {
                return reply.code(400).send('Missing parameters');
            }

            const isValid = validateSignature(config.wechat.token, signature, timestamp, nonce);

            if (isValid && echostr) {
                return reply.type('text/plain').send(echostr);
            }

            return reply.code(403).send('Invalid signature');
        }
    );

    /**
     * POST /wechat - Handle incoming WeChat messages
     * New flow: auto-provision VM on first message, route to internal IP
     */
    fastify.post<{ Querystring: WeChatQueryParams }>(
        '/wechat',
        {
            config: {
                rawBody: true,
            },
        },
        async (request, reply) => {
            const { signature, timestamp, nonce, encrypt_type, msg_signature } = request.query;

            // Validate signature
            if (!signature || !timestamp || !nonce) {
                return reply.code(400).send('Missing parameters');
            }

            const isValid = validateSignature(config.wechat.token, signature, timestamp, nonce);
            if (!isValid) {
                return reply.code(403).send('Invalid signature');
            }

            // Parse XML message
            let message;
            const body = request.body as string;
            const isEncrypted = encrypt_type === 'aes';

            try {
                if (isEncrypted) {
                    if (!config.wechat.encodingAESKey) {
                        console.error('Encrypted message received but WECHAT_ENCODING_AES_KEY not configured');
                        return reply.code(500).send('Encryption key not configured');
                    }

                    const encryptedContent = extractEncryptedContent(body);
                    if (!encryptedContent) {
                        return reply.code(400).send('Missing encrypted content');
                    }

                    if (msg_signature) {
                        const isValidMsgSig = validateMsgSignature(
                            config.wechat.token, timestamp, nonce,
                            encryptedContent, msg_signature
                        );
                        if (!isValidMsgSig) {
                            return reply.code(403).send('Invalid msg_signature');
                        }
                    }

                    const decryptedXml = decryptMessage(
                        encryptedContent,
                        config.wechat.encodingAESKey,
                        config.wechat.appId
                    );
                    message = parseWeChatXml(decryptedXml);
                } else {
                    message = parseWeChatXml(body);
                }
            } catch (error) {
                console.error('Failed to parse/decrypt WeChat message:', error);
                return reply.code(400).send('Invalid message');
            }

            const openId = message.FromUserName;
            const toUser = message.ToUserName;

            /**
             * Helper to send reply (handles encryption if needed)
             */
            const sendReply = (plainXml: string) => {
                if (isEncrypted && config.wechat.encodingAESKey) {
                    const encrypted = encryptMessage(plainXml, config.wechat.encodingAESKey, config.wechat.appId);
                    const replyTimestamp = String(Math.floor(Date.now() / 1000));
                    const replyNonce = String(Math.floor(Math.random() * 1000000000));
                    const replySignature = generateMsgSignature(
                        config.wechat.token, replyTimestamp, replyNonce, encrypted
                    );
                    return reply.type('text/xml').send(
                        buildEncryptedReply(encrypted, replySignature, replyTimestamp, replyNonce)
                    );
                } else {
                    return reply.type('text/xml').send(plainXml);
                }
            };

            // ========== EVENT HANDLING ==========
            if (message.MsgType === 'event') {
                if (message.Event === 'subscribe') {
                    // New follower → auto-provision VM
                    return handleNewUser(openId, toUser, sendReply);
                }
                return reply.type('text/plain').send('');
            }

            // ========== COMMAND HANDLING ==========
            if (message.MsgType === 'text' && message.Content) {
                const content = message.Content.trim();

                if (HELP_REGEX.test(content)) {
                    const sshHost = config.bridge.sshHost;
                    const sshPort = config.bridge.sshPort;
                    return sendReply(buildTextReply(openId, toUser,
                        `🤖 Clawdbot 云助手\n\n可用指令：\n• status - 查看 VM 状态\n• restart - 重启 VM\n• stop - 停止 VM\n• destroy - 销毁 VM 及数据\n• passwd <新密码> - 修改 SSH 密码\n• help - 显示帮助\n\n🖥 SSH 连接：\nssh ${openId}@${sshHost} -p ${sshPort}\n\n直接发送消息即可与 AI 对话。`
                    ));
                }

                if (STATUS_REGEX.test(content)) {
                    return handleStatusCommand(openId, toUser, sendReply);
                }

                if (RESTART_REGEX.test(content)) {
                    return handleRestartCommand(openId, toUser, sendReply);
                }

                if (STOP_REGEX.test(content)) {
                    return handleStopCommand(openId, toUser, sendReply);
                }

                if (DESTROY_REGEX.test(content)) {
                    return handleDestroyCommand(openId, toUser, sendReply);
                }

                const passwdMatch = content.match(PASSWD_REGEX);
                if (passwdMatch) {
                    return handlePasswdCommand(openId, toUser, passwdMatch[1], sendReply);
                }
            }

            // ========== MESSAGE ROUTING ==========
            const binding = await getVMBinding(openId);

            if (!binding) {
                // No VM yet → auto-provision
                return handleNewUser(openId, toUser, sendReply);
            }

            switch (binding.status) {
                case 'provisioning':
                    return sendReply(buildTextReply(openId, toUser,
                        '⏳ 你的 Clawdbot 正在启动中，请稍等几秒后再发送消息...'
                    ));

                case 'stopped':
                    // Auto-restart on message
                    return handleRestartCommand(openId, toUser, sendReply);

                case 'error':
                    return sendReply(buildTextReply(openId, toUser,
                        `❌ VM 状态异常: ${binding.errorMessage || '未知错误'}\n\n发送 restart 尝试重启，或 destroy 后重新关注。`
                    ));

                case 'running':
                    // Forward message to VM
                    await updateVMBindingStatus(openId, 'running');
                    forwardToClawdbot(message, binding);
                    return sendReply(
                        buildTextReply(openId, toUser, '⏳ 正在处理中，请稍候...')
                    );

                default:
                    return sendReply(buildTextReply(openId, toUser,
                        '⚠️ 未知状态，请发送 help 查看可用指令。'
                    ));
            }
        }
    );

    // ========== HANDLER FUNCTIONS ==========

    /**
     * Handle new user: provision a VM and reply with SSH info.
     */
    async function handleNewUser(
        openId: string,
        toUser: string,
        sendReply: (xml: string) => void
    ) {
        // Set provisioning status immediately
        const initialBinding: VMBinding = {
            vmIp: '',
            webhookUrl: '',
            status: 'provisioning',
            createdAt: Date.now(),
            lastActiveAt: Date.now(),
        };
        await setVMBinding(openId, initialBinding);

        // Trigger VM creation asynchronously
        provisionVMAsync(openId);

        return sendReply(buildTextReply(openId, toUser,
            `👋 欢迎使用 Clawdbot 云智能体！\n\n🚀 正在为你分配专属 AI 环境，通常需要 10-30 秒...\n\n启动完成后，你可以直接发送消息与 AI 对话。\n\n发送 help 查看所有可用指令。`
        ));
    }

    /**
     * Asynchronously provision a VM via the Orchestrator.
     * Updates the Redis binding on completion.
     */
    async function provisionVMAsync(openId: string): Promise<void> {
        try {
            console.log(`[Provision] Starting VM for ${openId}`);
            const vmInfo: VMInfo = await orchestrator.createVM(openId);

            const binding: VMBinding = {
                vmIp: vmInfo.vm_ip,
                webhookUrl: vmInfo.webhook_url,
                status: vmInfo.status === 'running' ? 'running' : 'provisioning',
                createdAt: Date.now(),
                lastActiveAt: Date.now(),
            };
            await setVMBinding(openId, binding);

            console.log(`[Provision] VM ready for ${openId}: IP=${vmInfo.vm_ip}`);

            // Send SSH info via Customer Service API (async)
            const { sendTextMessage } = await import('../services/wechat-message.js');
            const sshHost = config.bridge.sshHost;
            const sshPort = config.bridge.sshPort;
            await sendTextMessage(openId,
                `✅ 你的 Clawdbot 已就绪！\n\n` +
                `🖥 SSH 连接：\nssh ${openId}@${sshHost} -p ${sshPort}\n` +
                `密码: clawdbot\n\n` +
                `现在可以直接发送消息与 AI 对话了。`
            );
        } catch (error) {
            console.error(`[Provision] Failed for ${openId}:`, error);
            await updateVMBindingStatus(openId, 'error', {
                errorMessage: error instanceof Error ? error.message : String(error),
            });

            try {
                const { sendTextMessage } = await import('../services/wechat-message.js');
                await sendTextMessage(openId,
                    `❌ OpenClaw 启动失败，请稍后重试。\n\n发送 restart 尝试重新启动。`
                );
            } catch {
                // Ignore send failure
            }
        }
    }

    /**
     * Handle `status` command
     */
    async function handleStatusCommand(
        openId: string,
        toUser: string,
        sendReply: (xml: string) => void
    ) {
        const binding = await getVMBinding(openId);
        if (!binding) {
            return sendReply(buildTextReply(openId, toUser,
                '📭 你还没有运行中的 Clawdbot 实例。\n\n发送任意消息即可自动创建。'
            ));
        }

        const statusEmoji: Record<string, string> = {
            provisioning: '🔄',
            running: '🟢',
            stopped: '🔴',
            error: '❌',
        };

        const sshHost = config.bridge.sshHost;
        const sshPort = config.bridge.sshPort;
        const createdDate = new Date(binding.createdAt).toLocaleString('zh-CN');
        return sendReply(buildTextReply(openId, toUser,
            `${statusEmoji[binding.status] || '❓'} VM 状态: ${binding.status}\n` +
            `🖥 IP: ${binding.vmIp || 'N/A'}\n` +
            `🔌 SSH: ssh ${openId}@${sshHost} -p ${sshPort}\n` +
            `📅 创建时间: ${createdDate}`
        ));
    }

    /**
     * Handle `restart` command
     */
    async function handleRestartCommand(
        openId: string,
        toUser: string,
        sendReply: (xml: string) => void
    ) {
        await updateVMBindingStatus(openId, 'provisioning');

        // Trigger restart asynchronously
        (async () => {
            try {
                const vmInfo = await orchestrator.startVM(openId);
                const binding: VMBinding = {
                    vmIp: vmInfo.vm_ip,
                    webhookUrl: vmInfo.webhook_url,
                    status: 'running',
                    createdAt: Date.now(),
                    lastActiveAt: Date.now(),
                };
                await setVMBinding(openId, binding);

                const { sendTextMessage } = await import('../services/wechat-message.js');
                await sendTextMessage(openId, '✅ Clawdbot 已重新启动！');
            } catch (err) {
                console.error(`[Restart] Failed for ${openId}:`, err);
                await updateVMBindingStatus(openId, 'error', {
                    errorMessage: err instanceof Error ? err.message : String(err),
                });
            }
        })();

        return sendReply(buildTextReply(openId, toUser,
            '🔄 正在重启 Clawdbot，请稍候...'
        ));
    }

    /**
     * Handle `stop` command
     */
    async function handleStopCommand(
        openId: string,
        toUser: string,
        sendReply: (xml: string) => void
    ) {
        try {
            await orchestrator.stopVM(openId);
            await updateVMBindingStatus(openId, 'stopped');
            return sendReply(buildTextReply(openId, toUser,
                '🔴 Clawdbot 已停止。\n\n发送 restart 可重新启动，数据已保留。'
            ));
        } catch (err) {
            console.error(`[Stop] Failed for ${openId}:`, err);
            return sendReply(buildTextReply(openId, toUser,
                '❌ 停止失败，请稍后重试。'
            ));
        }
    }

    /**
     * Handle `destroy` command
     */
    async function handleDestroyCommand(
        openId: string,
        toUser: string,
        sendReply: (xml: string) => void
    ) {
        try {
            await orchestrator.destroyVM(openId);
            await deleteVMBinding(openId);
            return sendReply(buildTextReply(openId, toUser,
                '🗑️ Clawdbot 已销毁，所有数据已删除。\n\n发送任意消息可重新创建。'
            ));
        } catch (err) {
            console.error(`[Destroy] Failed for ${openId}:`, err);
            return sendReply(buildTextReply(openId, toUser,
                '❌ 销毁失败，请稍后重试。'
            ));
        }
    }

    /**
     * Handle `passwd <new_password>` command
     */
    async function handlePasswdCommand(
        openId: string,
        toUser: string,
        newPassword: string,
        sendReply: (xml: string) => void
    ) {
        if (newPassword.length < 6) {
            return sendReply(buildTextReply(openId, toUser,
                '❌ 密码长度至少 6 个字符。\n\n用法: passwd <新密码>'
            ));
        }

        try {
            await orchestrator.changePassword(openId, newPassword);
            return sendReply(buildTextReply(openId, toUser,
                '✅ SSH 密码已修改成功！\n\n新密码将在下次 SSH 连接时生效。'
            ));
        } catch (err) {
            console.error(`[Passwd] Failed for ${openId}:`, err);
            return sendReply(buildTextReply(openId, toUser,
                '❌ 密码修改失败，请确认 VM 处于运行状态后重试。'
            ));
        }
    }
}
