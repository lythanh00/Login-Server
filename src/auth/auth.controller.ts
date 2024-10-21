import {
  Controller,
  Post,
  HttpCode,
  HttpStatus,
  Body,
  UseGuards,
  Get,
  Request,
  Res,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { LoginDto } from './dtos/login.dto';
import { RegisterDto } from './dtos/register.dto';
import { AuthGuard } from './guard/auth.guard';
// import { LocalAuthGuard } from './guard/local-auth.guard';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  //   @UseGuards(LocalAuthGuard)
  @HttpCode(HttpStatus.OK)
  @Post('login')
  async login(@Body() loginDto: LoginDto) {
    await this.authService.login(loginDto.email, loginDto.password);

    return true;
  }

  @Post('verify-otp')
  async verifyOTP(@Body() otpDto: { otp: string; email: string }) {
    const { otp, email } = otpDto;

    return await this.authService.verifyOTP(otp, email);
  }

  @Post('/refresh')
  refresh(
    @Body('refreshToken') refreshToken: string,
  ): Promise<{ access_token: string }> {
    return this.authService.refreshToken(refreshToken);
  }

  @Post('/register')
  signUp(@Body() registerDto: RegisterDto) {
    return this.authService.register(registerDto.email, registerDto.password);
  }

  @UseGuards(AuthGuard)
  @Get('profile')
  async getProfile(@Request() req) {
    console.log('req.user.id', req.user.id);
    return {
      name: 'ly tien thanh',
      email: 'lytienthanhs1@gmail.com',
    };
  }
}
