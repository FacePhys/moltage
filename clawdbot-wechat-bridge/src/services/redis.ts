import Redis from 'ioredis';
import { getConfig } from '../config.js';

/**
 * VM binding structure (replaces the old UserBinding).
 * Maps a WeChat openid to a MicroVM in the VPC.
 */
export interface VMBinding {
    vmIp: string;          // Internal VPC IP (e.g., "10.0.1.42")
    webhookUrl: string;    // http://<vmIp>:3000/webhook
    status: 'provisioning' | 'running' | 'stopped' | 'error';
    createdAt: number;
    lastActiveAt: number;
    errorMessage?: string;
    ssh_password?: string; // Per-user SSH password (set via passwd command)
}

const VM_BINDING_PREFIX = 'vm:binding:';

let redisClient: Redis | null = null;

/**
 * Get Redis client singleton
 */
export function getRedis(): Redis {
    if (!redisClient) {
        const config = getConfig();
        redisClient = new Redis(config.redis.url);

        redisClient.on('error', (err) => {
            console.error('Redis connection error:', err);
        });

        redisClient.on('connect', () => {
            console.log('Connected to Redis');
        });
    }
    return redisClient;
}

/**
 * Set VM binding for a user (openid → VM info)
 */
export async function setVMBinding(
    openId: string,
    binding: VMBinding
): Promise<void> {
    const redis = getRedis();
    await redis.set(VM_BINDING_PREFIX + openId, JSON.stringify(binding));
}

/**
 * Get VM binding by OpenID
 */
export async function getVMBinding(openId: string): Promise<VMBinding | null> {
    const redis = getRedis();
    const data = await redis.get(VM_BINDING_PREFIX + openId);
    if (!data) return null;
    try {
        return JSON.parse(data) as VMBinding;
    } catch {
        return null;
    }
}

/**
 * Update VM binding status
 */
export async function updateVMBindingStatus(
    openId: string,
    status: VMBinding['status'],
    extraFields?: Partial<VMBinding>
): Promise<void> {
    const binding = await getVMBinding(openId);
    if (!binding) return;
    binding.status = status;
    binding.lastActiveAt = Date.now();
    if (extraFields) {
        Object.assign(binding, extraFields);
    }
    await setVMBinding(openId, binding);
}

/**
 * Delete VM binding
 */
export async function deleteVMBinding(openId: string): Promise<boolean> {
    const redis = getRedis();
    const result = await redis.del(VM_BINDING_PREFIX + openId);
    return result > 0;
}

/**
 * Check if user has a VM binding
 */
export async function hasVMBinding(openId: string): Promise<boolean> {
    const redis = getRedis();
    return (await redis.exists(VM_BINDING_PREFIX + openId)) > 0;
}

/**
 * Close Redis connection (for graceful shutdown)
 */
export async function closeRedis(): Promise<void> {
    if (redisClient) {
        await redisClient.quit();
        redisClient = null;
    }
}
