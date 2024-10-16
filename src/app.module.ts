import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { AppController } from './app.controller';
import { AppService } from './app.service';
// import { AuthModule } from './auth/auth.module';

import { LoggerModule } from './logger/logger.module';
import { SendgridModule } from './sendgrid/sendgrid.module';

import { TypeOrmModule } from '@nestjs/typeorm';
import { typeOrmConfigAsync } from './database/typeorm.config'; // Import cấu hình async

@Module({
  imports: [
    ConfigModule.forRoot({ ignoreEnvFile: true }),

    // AuthModule,

    // SendgridModule,
    LoggerModule.forRoot(),
    ConfigModule, // Import ConfigModule để sử dụng ConfigService
    TypeOrmModule.forRootAsync(typeOrmConfigAsync),
  ],
  controllers: [AppController],
  providers: [AppService],
  exports: [AppService],
})
export class AppModule {}
