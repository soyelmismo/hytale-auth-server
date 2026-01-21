const storage = require('../../../src/services/storage');

describe('Storage Service', () => {
  // Reference the shared mock from setup.js
  const getMockRedis = () => global.mockRedis;

  beforeEach(() => {
    // Use the global mockRedis from setup.js
    getMockRedis().__clear();
    jest.clearAllMocks();
  });

  describe('registerSession', () => {
    it('should register a session in Redis', async () => {
      const sessionToken = 'test-session-token';
      const uuid = 'test-uuid';
      const username = 'TestPlayer';
      const serverAudience = 'server-123';

      await storage.registerSession(sessionToken, uuid, username, serverAudience);

      expect(getMockRedis().setex).toHaveBeenCalled();
    });

    it('should cache username when valid', async () => {
      const uuid = 'test-uuid';
      const username = 'ValidName';

      await storage.registerSession('token', uuid, username, null);

      // Username should be cached
      const cached = storage.getCachedUsername(uuid);
      expect(cached).toBe(username);
    });

    it('should not cache "Player" username', async () => {
      const uuid = 'test-uuid-2';

      await storage.registerSession('token', uuid, 'Player', null);

      const cached = storage.getCachedUsername(uuid);
      expect(cached).toBeUndefined();
    });
  });

  describe('registerAuthGrant', () => {
    it('should register auth grant with player-server mapping', async () => {
      const authGrant = 'auth-grant-token';
      const playerUuid = 'player-123';
      const playerName = 'Player';
      const serverAudience = 'server-456';

      await storage.registerAuthGrant(authGrant, playerUuid, playerName, serverAudience);

      expect(getMockRedis().setex).toHaveBeenCalled();
      expect(getMockRedis().sadd).toHaveBeenCalled();
    });
  });

  describe('removeSession', () => {
    it('should remove session and clean up mappings', async () => {
      const sessionToken = 'remove-session-token';
      const sessionData = {
        uuid: 'player-uuid',
        username: 'Player',
        serverAudience: 'server-123',
      };

      getMockRedis()._data.set(`session:${sessionToken}`, JSON.stringify(sessionData));
      getMockRedis()._data.set(`server:${sessionData.serverAudience}`, new Set([sessionData.uuid]));

      const result = await storage.removeSession(sessionToken);

      expect(result).toBe(true);
      expect(getMockRedis().del).toHaveBeenCalled();
    });

    it('should return false when session not found', async () => {
      const result = await storage.removeSession('non-existent-token');
      expect(result).toBe(false);
    });
  });

  describe('getUserData', () => {
    it('should return user data from Redis', async () => {
      const uuid = 'user-uuid';
      const userData = { username: 'TestUser', skin: { color: '#fff' } };

      getMockRedis()._data.set(`user:${uuid}`, JSON.stringify(userData));

      const result = await storage.getUserData(uuid);

      expect(result).toEqual(userData);
    });

    it('should return empty object when user not found', async () => {
      const result = await storage.getUserData('non-existent-uuid');
      expect(result).toEqual({});
    });
  });

  describe('saveUserData', () => {
    it('should save user data to Redis', async () => {
      const uuid = 'save-user-uuid';
      const data = { username: 'SavedUser', skin: {} };

      await storage.saveUserData(uuid, data);

      expect(getMockRedis().set).toHaveBeenCalled();
    });

    it('should also persist username if present', async () => {
      const uuid = 'user-with-name';
      const data = { username: 'PersistedName' };

      await storage.saveUserData(uuid, data);

      const cached = storage.getCachedUsername(uuid);
      expect(cached).toBe('PersistedName');
    });
  });

  describe('persistUsername', () => {
    it('should persist username to cache and Redis', async () => {
      const uuid = 'persist-uuid';
      const name = 'PersistedPlayer';

      await storage.persistUsername(uuid, name);

      expect(storage.getCachedUsername(uuid)).toBe(name);
      expect(getMockRedis().set).toHaveBeenCalled();
    });

    it('should not persist "Player" username', async () => {
      const uuid = 'no-persist-uuid';

      await storage.persistUsername(uuid, 'Player');

      expect(storage.getCachedUsername(uuid)).toBeUndefined();
    });

    it('should not persist empty username', async () => {
      const uuid = 'empty-name-uuid';

      await storage.persistUsername(uuid, '');

      expect(getMockRedis().set).not.toHaveBeenCalled();
    });
  });

  describe('getUsername', () => {
    it('should return cached username first', async () => {
      const uuid = 'cached-uuid';
      storage.setCachedUsername(uuid, 'CachedName');

      const result = await storage.getUsername(uuid);

      expect(result).toBe('CachedName');
    });

    it('should fetch from Redis if not cached', async () => {
      const uuid = 'redis-uuid';
      getMockRedis()._data.set(`username:${uuid}`, 'RedisName');

      const result = await storage.getUsername(uuid);

      expect(result).toBe('RedisName');
    });

    it('should return null if not found anywhere', async () => {
      const result = await storage.getUsername('unknown-uuid');
      expect(result).toBeNull();
    });
  });

  describe('Admin Token Management', () => {
    describe('createAdminToken', () => {
      it('should create admin token in Redis', async () => {
        const token = 'admin-token-123';

        const result = await storage.createAdminToken(token);

        expect(result).toBe(true);
        expect(getMockRedis().setex).toHaveBeenCalled();
      });
    });

    describe('verifyAdminToken', () => {
      it('should return true for valid token', async () => {
        const token = 'valid-admin-token';
        getMockRedis()._data.set(`admintoken:${token}`, '1');

        const result = await storage.verifyAdminToken(token);

        expect(result).toBe(true);
      });

      it('should return false for invalid token', async () => {
        const result = await storage.verifyAdminToken('invalid-token');
        expect(result).toBe(false);
      });

      it('should return false for null token', async () => {
        const result = await storage.verifyAdminToken(null);
        expect(result).toBe(false);
      });
    });
  });

  describe('Server Name Management', () => {
    describe('setServerName', () => {
      it('should set server name in Redis', async () => {
        const result = await storage.setServerName('server-123', 'My Server');

        expect(result).toBe(true);
        expect(getMockRedis().set).toHaveBeenCalled();
      });

      it('should return false for missing audience', async () => {
        const result = await storage.setServerName(null, 'Name');
        expect(result).toBe(false);
      });

      it('should return false for missing name', async () => {
        const result = await storage.setServerName('server', null);
        expect(result).toBe(false);
      });
    });

    describe('getServerName', () => {
      it('should return server name from Redis', async () => {
        getMockRedis()._data.set('servername:server-123', 'My Server');

        const result = await storage.getServerName('server-123');

        expect(result).toBe('My Server');
      });

      it('should return null for missing server', async () => {
        const result = await storage.getServerName('unknown-server');
        expect(result).toBeNull();
      });
    });
  });

  describe('getAllActiveSessions', () => {
    it('should return empty arrays when no sessions', async () => {
      const result = await storage.getAllActiveSessions();

      expect(result).toEqual({ sessions: [], servers: [] });
    });
  });

  describe('getPlayersOnServer', () => {
    it('should return players on specified server', async () => {
      const serverAudience = 'server-with-players';
      const playerSet = new Set(['uuid-1', 'uuid-2']);
      getMockRedis()._data.set(`server:${serverAudience}`, playerSet);
      getMockRedis()._data.set('username:uuid-1', 'Player1');
      getMockRedis()._data.set('username:uuid-2', 'Player2');

      const result = await storage.getPlayersOnServer(serverAudience);

      expect(result).toHaveLength(2);
      expect(result.map(p => p.uuid)).toContain('uuid-1');
      expect(result.map(p => p.uuid)).toContain('uuid-2');
    });

    it('should return empty array for server with no players', async () => {
      const result = await storage.getPlayersOnServer('empty-server');
      expect(result).toEqual([]);
    });
  });

  describe('findPlayerOnServer', () => {
    it('should find player by username on server', async () => {
      const serverAudience = 'search-server';
      // Use unique UUIDs to avoid cache interference from other tests
      const playerSet = new Set(['search-uuid-1']);
      getMockRedis()._data.set(`server:${serverAudience}`, playerSet);
      getMockRedis()._data.set('username:search-uuid-1', 'TargetPlayer');

      const result = await storage.findPlayerOnServer(serverAudience, 'TargetPlayer');

      expect(result).toHaveLength(1);
      expect(result[0].uuid).toBe('search-uuid-1');
    });

    it('should be case-insensitive', async () => {
      const serverAudience = 'case-server';
      // Use unique UUIDs to avoid cache interference from other tests
      const playerSet = new Set(['case-uuid-1']);
      getMockRedis()._data.set(`server:${serverAudience}`, playerSet);
      getMockRedis()._data.set('username:case-uuid-1', 'CamelCase');

      const result = await storage.findPlayerOnServer(serverAudience, 'camelcase');

      expect(result).toHaveLength(1);
    });
  });

  describe('isRedisConnected', () => {
    it('should return true when redis is connected', () => {
      // The mock setup in setup.js sets isConnected to return true
      const result = storage.isRedisConnected();
      expect(result).toBe(true);
    });
  });

  describe('getKeyCounts', () => {
    it('should return key counts from Redis', async () => {
      const result = await storage.getKeyCounts();

      expect(result).toHaveProperty('sessions');
      expect(result).toHaveProperty('authGrants');
      expect(result).toHaveProperty('users');
      expect(result).toHaveProperty('servers');
      expect(result).toHaveProperty('activePlayers');
    });

    it('should return zeros when Redis is empty', async () => {
      const result = await storage.getKeyCounts();

      expect(result.sessions).toBe(0);
      expect(result.authGrants).toBe(0);
      expect(result.users).toBe(0);
      expect(result.servers).toBe(0);
      expect(result.activePlayers).toBe(0);
    });
  });

  describe('getPaginatedServers', () => {
    it('should return paginated server list', async () => {
      const result = await storage.getPaginatedServers(1, 10);

      expect(result).toHaveProperty('servers');
      expect(result).toHaveProperty('pagination');
      expect(result.pagination).toHaveProperty('page');
      expect(result.pagination).toHaveProperty('limit');
      expect(result.pagination).toHaveProperty('totalServers');
      expect(result.pagination).toHaveProperty('totalPages');
      expect(result.pagination).toHaveProperty('hasNext');
      expect(result.pagination).toHaveProperty('hasPrev');
    });

    it('should return empty servers when no data', async () => {
      const result = await storage.getPaginatedServers(1, 10);

      expect(result.servers).toHaveLength(0);
      expect(result.pagination.totalServers).toBe(0);
    });
  });

  describe('getAllPlayerUuids', () => {
    it('should return all unique player UUIDs', async () => {
      const result = await storage.getAllPlayerUuids();

      expect(Array.isArray(result)).toBe(true);
    });

    it('should return empty array when no players', async () => {
      const result = await storage.getAllPlayerUuids();

      expect(result).toHaveLength(0);
    });
  });
});
