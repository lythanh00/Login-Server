import {
  HttpStatus,
  Injectable,
  Res,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UsersService } from 'users/users.service';
import * as bcrypt from 'bcrypt';
import { authenticator } from 'otplib';
import { EmailService } from './email.service';

@Injectable()
export class AuthService {
  private secret: string;
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
    private emailService: EmailService,
  ) {
    this.secret = authenticator.generateSecret();
  }

  async login(email: string, password: string) {
    const user = await this.usersService.getUserByEmail(email);
    if (!user) {
      throw new UnauthorizedException('Invalid email');
    }

    const isPasswordMatched = await bcrypt.compare(password, user.password);

    if (!isPasswordMatched) {
      throw new UnauthorizedException('Invalid password');
    }

    const otp = await this.generateOTP();

    await this.emailService.sendEmail(email, otp);

    return true;

    // const payload = { id: user.id, email: user.email };

    // const accessToken = await this.jwtService.signAsync(payload);
    // const refreshToken = await this.jwtService.signAsync(payload, {
    //   expiresIn: '30d', // Thời gian sống cho refresh token
    // });

    // return {
    //   access_token: accessToken,
    //   refresh_token: refreshToken,
    // };
  }

  async refreshToken(refreshToken: string): Promise<{ access_token: string }> {
    try {
      const payload = await this.jwtService.verifyAsync(refreshToken);
      const newAccessToken = await this.jwtService.signAsync({
        id: payload.id,
        email: payload.email,
      });
      return { access_token: newAccessToken };
    } catch (error) {
      throw new UnauthorizedException('Invalid refresh token');
    }
  }

  async register(email: string, password: string) {
    const hashedPassword = await bcrypt.hash(password, 10);
    const res = await this.usersService.getUserByEmail(email);
    if (res?.id) {
      throw new UnauthorizedException('username already in used');
    }
    try {
      const user = await this.usersService.createUser(email, hashedPassword);
    } catch (E11000) {
      throw new UnauthorizedException('email already in used');
    }
  }

  async generateOTP() {
    // Tạo mã OTP dựa trên khóa bí mật
    authenticator.options = { step: 60 * 2 };
    const otp = authenticator.generate(this.secret);
    return otp;
  }

  async verifyOTP(token: string, email: string) {
    // Xác minh mã OTP
    const isValid = await authenticator.verify({ token, secret: this.secret });

    if (!isValid) {
      return false;
    } else {
      const user = await this.usersService.getUserByEmail(email);
      const payload = { id: user.id, email: user.email };

      const accessToken = await this.jwtService.signAsync(payload);
      const refreshToken = await this.jwtService.signAsync(payload, {
        expiresIn: '30d', // Thời gian sống cho refresh token
      });

      return {
        access_token: accessToken,
        refresh_token: refreshToken,
      };
    }
  }
}
