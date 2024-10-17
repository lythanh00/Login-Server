// src/database/typeorm.config.ts
import { TypeOrmModuleOptions } from '@nestjs/typeorm';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { User } from 'database/user.entity';

export const typeOrmConfigAsync = {
  imports: [ConfigModule],
  useFactory: (configService: ConfigService): TypeOrmModuleOptions => ({
    type: 'mysql',
    host: 'localhost',
    port: 3306,
    username: 'root',
    password: '070902',
    database: 'login',
    entities: [User], // Danh sách các entity
    synchronize: true, // Chỉ dùng trong môi trường phát triển
  }),
  inject: [ConfigService],
};
