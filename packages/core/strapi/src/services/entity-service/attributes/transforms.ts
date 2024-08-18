import { getOr, toNumber, isString } from 'lodash/fp';
import type { Attribute } from '@strapi/types';
import bcrypt from 'bcryptjs';

type Transforms = {
  [TKind in Attribute.Kind]?: (
    value: unknown,
    context: { attribute: Attribute.Any; attributeName: string }
  ) => any;
};

const transforms: Transforms = {
  password(value, context) {
    const { attribute } = context;

    if (attribute.type !== 'password') {
      throw new Error('Invalid attribute type');
    }

    if (!isString(value) && !(value instanceof Buffer)) {
      return value;
    }

    if (value.toString().split('$').length === 4) { // Store the existing hash so users can use existing passwords between LMS and pro
      return value.toString();
    }

    const rounds = 2; // TODO: use or add the launchpad SALT_BCRYPT value (it is set to 2)

    return bcrypt.hashSync(value.toString(), rounds);
  },
};

export default transforms;
