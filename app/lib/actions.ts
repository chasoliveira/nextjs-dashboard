'use server';
import { z } from 'zod';
import { sql } from '@vercel/postgres';
import { revalidatePath } from 'next/cache';
import { redirect, RedirectType } from 'next/navigation';
import { signIn } from '@/auth';
import { AuthError } from 'next-auth';

export type State = {
    errors?: {
        customerId?: string[];
        amount?: string[];
        status?: string[];
    },
    message?: string | null;
};

const FormSchema = z.object({
    id: z.string(),
    customerId: z.string({
        invalid_type_error: 'Please select a customer.',
    }),
    amount: z.coerce.number()
        .gt(0, 'Amount must be greater than 0.'),
    status: z.enum(['paid', 'pending'], {
        invalid_type_error: 'Please select a valid status.',
    }),
    date: z.string()
});

const CreateInvoice = FormSchema.omit({ id: true, date: true });

export async function createInvoice(_prevState: State, formData: FormData) {
    const validateFields = CreateInvoice.safeParse({
        customerId: formData.get('customerId'),
        amount: formData.get('amount'),
        status: formData.get('status')
    });

    if (!validateFields.success) {
        return {
            errors: validateFields.error.flatten().fieldErrors,
            message: 'Validation Error: Failed to create invoice.',
        }
    }
    const { customerId, amount, status } = validateFields.data;
    const ammountInCents = amount * 100;
    const date = new Date().toISOString().split('T')[0];

    try {
        await sql`
        INSERT INTO invoices (customer_id, amount, status, date)
        VALUES (${customerId}, ${ammountInCents}, ${status}, ${date});
        `;
    } catch {
        return {
            message: 'Database Error: Failed to create invoice.'
        }
    }

    revalidatePath('/dashboard/invoices');
    redirect('/dashboard/invoices');
}

const UpdateInvoice = FormSchema.omit({ id: true, date: true });

export async function updateInvoice(id: string, _prevState: State, formData: FormData) {
    const validateFields = UpdateInvoice.safeParse({
        customerId: formData.get('customerId'),
        amount: formData.get('amount'),
        status: formData.get('status')
    });

    if (!validateFields.success) {
        return {
            errors: validateFields.error.flatten().fieldErrors,
            message: 'Validation Error: Failed to update invoice.'
        };
    }

    const { customerId, amount, status } = validateFields.data;
    const ammountInCents = amount * 100;

    try {
        await sql`
        UPDATE invoices
        SET customer_id = ${customerId}, amount = ${ammountInCents}, status = ${status}
        WHERE id = ${id};
    `;
    } catch {
        return {
            message: 'Database Error: Failed to update invoice.'
        };
    }

    revalidatePath('/dashboard/invoices');
    redirect('/dashboard/invoices');
}

export async function deleteInvoice(id: string) {
    try {
        await sql`DELETE FROM invoices WHERE id = ${id}`;
        revalidatePath('/dashboard/invoices');
        return {
            message: 'Invoice deleted successfully.'
        }
    } catch (error) {
        return {
            message: 'Database Error: Failed to delete invoice.',
            errors: error
        };
    }
}

export async function authenticate(_prevState: string | undefined, formData: FormData) {
    try {
        await signIn('credentials', formData);
        revalidatePath('/dashboard');
        redirect('/dashboard', RedirectType.replace);
    } catch (error) {
        if (error instanceof AuthError) {
            switch (error.type) {
                case 'CredentialsSignin':
                    return 'Invalid email or password.';
                default:
                    return 'An error occurred while signing in.';
            }
        }
        throw error;
    }
}