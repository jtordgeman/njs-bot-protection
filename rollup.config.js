import typescript from '@rollup/plugin-typescript';

export default {
    input: 'src/bot.ts',
    output: {
        dir: 'dist',
    },
    plugins: [typescript()],
};
