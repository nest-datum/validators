import getCurrentLine from 'get-current-line';
import { WarningException } from '@nest-datum/exceptions';
import { checkToken } from '@nest-datum/jwt';

export const token = (propertyName: string, value, options = {}) => {
	if (!options['secret']
		|| typeof options['secret'] !== 'string') {
		throw new WarningException(`"secret" property is incorrect in token${propertyName ? ` "${propertyName}" `: ''}validation.`, getCurrentLine(), { value, ...options });
	}
	if (!options['timeout']
		&& typeof options['timeout'] !== 'number'
		&& typeof options['timeout'] !== 'string') {
		throw new WarningException(`"timeout" property is incorrect in token${propertyName ? ` "${propertyName}" `: ''}validation.`, getCurrentLine(), { value, ...options });
	}
	options['timeout'] = Number(options['timeout']);

	if (value !== 'null') {
		if (!(options['timeout'] > 0)) {
			throw new WarningException(`"timeout" property with bad value in token${propertyName ? ` "${propertyName}" `: ''}validation.`, getCurrentLine(), { value, ...options });
		}
	}

	if (typeof value !== 'undefined') {
		if (typeof value === 'string') {
			if (value === 'null') {
				return {
					[propertyName]: value,
					authFlag: false,
				};
			}
			try {
				const userData = JSON.parse(Buffer.from((value.split('.'))[1], 'base64').toString());

				if (!checkToken(value, options['secret'], {
					...userData,
					exp: (options['timeout'] || '').toString(),
				})) {
					throw new Error(`Token${propertyName ? ` "${propertyName}" `: ''}is not valid.`);
				}
				return {
					[propertyName]: value,
					...userData,
				};
			}
			catch (err) {
				throw new WarningException(err.message, getCurrentLine(), { value, ...options });
			}
		}
		throw new WarningException(`Token${propertyName ? ` "${propertyName}" `: ''}is incorrect.`, getCurrentLine(), { value, ...options });
	}
	else if (options['isRequired']) {
		throw new WarningException(`Token${propertyName ? ` "${propertyName}" `: ''}is empty.`, getCurrentLine(), { value, ...options });
	}
	return {
		[propertyName]: value,
		authFlag: false,
	};
};
