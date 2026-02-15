import axios, { AxiosInstance } from 'axios';
import { getConfig } from '../config.js';

/**
 * VM info returned by the Orchestrator API
 */
export interface VMInfo {
    user_id: string;
    status: 'provisioning' | 'running' | 'stopped' | 'error';
    vm_ip: string;
    webhook_url: string;
    created_at: string;
    stopped_at?: string;
    error_message?: string;
    resource_limits: {
        vcpu_count: number;
        mem_size_mib: number;
    };
}

/**
 * Client for communicating with the VM Orchestrator service.
 */
export class OrchestratorClient {
    private client: AxiosInstance;

    constructor() {
        const config = getConfig();
        this.client = axios.create({
            baseURL: config.orchestrator.url,
            timeout: config.orchestrator.vmReadyTimeoutMs,
            headers: { 'Content-Type': 'application/json' },
        });
    }

    /**
     * Request a new VM for the given user.
     * If the VM already exists, returns its current info.
     */
    async createVM(userId: string): Promise<VMInfo> {
        const response = await this.client.post<VMInfo>('/api/v1/vms', {
            user_id: userId,
        });
        return response.data;
    }

    /**
     * Get VM status and info for a user.
     * Returns null if no VM exists.
     */
    async getVMStatus(userId: string): Promise<VMInfo | null> {
        try {
            const response = await this.client.get<VMInfo>(`/api/v1/vms/${userId}`);
            return response.data;
        } catch (error: any) {
            if (error.response?.status === 404) {
                return null;
            }
            throw error;
        }
    }

    /**
     * Stop a user's VM (preserves data).
     */
    async stopVM(userId: string): Promise<void> {
        await this.client.post(`/api/v1/vms/${userId}/stop`);
    }

    /**
     * Restart a stopped VM.
     */
    async startVM(userId: string): Promise<VMInfo> {
        const response = await this.client.post<VMInfo>(`/api/v1/vms/${userId}/start`);
        return response.data;
    }

    /**
     * Destroy a VM and all its data.
     */
    async destroyVM(userId: string): Promise<void> {
        await this.client.delete(`/api/v1/vms/${userId}`);
    }

    /**
     * Change the SSH password for a user's VM.
     */
    async changePassword(userId: string, newPassword: string): Promise<void> {
        await this.client.post(`/api/v1/vms/${userId}/passwd`, {
            new_password: newPassword,
        });
    }
}

// Singleton instance
let orchestratorClient: OrchestratorClient | null = null;

export function getOrchestratorClient(): OrchestratorClient {
    if (!orchestratorClient) {
        orchestratorClient = new OrchestratorClient();
    }
    return orchestratorClient;
}
