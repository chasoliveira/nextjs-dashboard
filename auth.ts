import NextAuth from 'next-auth';
import { authConfig } from './auth.config';
import Credentials from 'next-auth/providers/credentials';
import { z } from 'zod';
import { User } from './app/lib/definitions';
import { sql } from '@vercel/postgres';
import bcrypt from 'bcrypt';

async function getUser(email: string): Promise<User | null> {
    try {
        const user = await sql<User>`SELECT * FROM users WHERE email = ${email}`;
        return user.rows[0] ?? null;
    } catch (error) {
        console.error(error);
        throw new Error('An error occurred while fetching the user');
    }
}
export const { auth, signIn, signOut } = NextAuth({
    ...authConfig,
    providers: [Credentials({
        async authorize(credentials) {
            const parsedCredentials = z.object({
                email: z.string().email(),
                password: z.string().min(6),
            }).safeParse(credentials);
            
            console.log(parsedCredentials);
            if (!parsedCredentials.success) return null;
            const { email, password } = parsedCredentials.data;
            const user = await getUser(email);

            if (!user) return null;
            const passwordMatches = await bcrypt.compare(password, user.password);
            console.log({passwordMatches, user});
            if (passwordMatches) return user;
            console.error('Password does not match');
            return null;
        }
    })]
});