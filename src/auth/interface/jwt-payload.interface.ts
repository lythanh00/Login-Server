import { RoleType } from '../../shared/enum/role-type.enum';

export interface JwtPayload {
  readonly id: number;
  readonly email: string;
}
