// src/config/config.module.ts
import { Module } from '@nestjs/common';
import { ConfigModule as NestConfigModule } from '@nestjs/config';

@Module({
  imports: [
    NestConfigModule.forRoot({
      isGlobal: true, // Để cấu hình có thể sử dụng toàn cục
    }),
  ],
})
export class ConfigModule {}
